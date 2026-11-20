import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

const app = express();

const PORT = process.env.PORT || 8000;

const allowedOrigins = [
  "http://localhost:3000",
  "https://fixmate-frontend-five.vercel.app",
];

app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(
  "/api/payments/webhook",
  express.raw({ type: "application/json" })
);

app.use(express.json());


const mongoUri = process.env.MONGODB_URI;

const client = new MongoClient(mongoUri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
const connectedClient = await connectToMongoDB();
const database = connectedClient.db("fixmate");
const users = database.collection("users");
const sessions = database.collection("sessions");
const payments = database.collection("payments");
const services = database.collection("services");
const serviceRequests = database.collection("serviceRequests");

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`),
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
await payments.createIndex(
  { stripeSessionId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      stripeSessionId: { $type: "string" },
    },
  }
);

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized. Please sign in.",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await jwtVerify(token, JWKS);

    req.user = payload;
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired token.",
    });
  }
};

// must call this middleware after verifyToken
const verifyCustomer = async (req, res, next) => {
  if (req.user.role !== "customer") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};

const verifyTechnician = async (req, res, next) => {
  if (req.user.role !== "technician") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};

const verifyAdmin = async (req, res, next) => {
  if (req.user.role !== "admin") {
    res.status(403).send({ message: "Forbidden" });
    return;
  }
  next();
};



// Services related APIs

app.post("/api/services", verifyToken, verifyTechnician, async (req, res) => {
  try {
    const {
      title,
      category,
      description,
      image,
      basePrice,
      estimatedDuration,
      serviceMode,
      serviceArea,
    } = req.body;

    // Validate required fields
    if (
      !title ||
      !category ||
      !description ||
      !image ||
      !estimatedDuration ||
      !serviceMode ||
      !serviceArea ||
      basePrice === undefined
    ) {
      return res.status(400).send({
        success: false,
        message: "Please provide all required fields.",
      });
    }

    const allowedCategories = [
      "Smartphone",
      "Laptop & PC",
      "AC",
      "Refrigerator",
      "TV",
      "Washing Machine",
      "Electrical",
    ];

    const allowedServiceModes = ["Home Visit", "Shop Drop-off"];

    if (!allowedCategories.includes(category)) {
      return res.status(400).send({
        success: false,
        message: "Invalid service category.",
      });
    }

    if (!allowedServiceModes.includes(serviceMode)) {
      return res.status(400).send({
        success: false,
        message: "Invalid service mode.",
      });
    }

    const price = Number(basePrice);

    if (!Number.isFinite(price) || price <= 0) {
      return res.status(400).send({
        success: false,
        message: "Please provide a valid service price.",
      });
    }

    // Get technician information from verified JWT claims.
    const technicianEmail = req.user.email;
    const technicianName = req.user.name;

    if (!technicianEmail || !technicianName) {
      return res.status(401).send({
        success: false,
        message: "Technician information is missing from the token.",
      });
    }

    const newService = {
      title: String(title).trim(),
      category,
      description: String(description).trim(),
      image: String(image).trim(),
      basePrice: price,
      estimatedDuration: String(estimatedDuration).trim(),
      serviceMode,
      serviceArea: String(serviceArea).trim(),

      technicianName,
      technicianEmail,

      approvalStatus: "pending",
      isAvailable: true,
      createdAt: new Date(),
    };

    const result = await services.insertOne(newService);

    res.status(201).send({
      success: true,
      message: "Service created successfully!",
      data: {
        _id: result.insertedId,
        ...newService,
      },
    });
  } catch (error) {
    console.error("Create service error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to create service.",
    });
  }
});

// Get services created by the logged-in technician
app.get(
  "/api/services/my-services",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).send({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      const result = await services
        .find({ technicianEmail })
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).send({
        success: true,
        message: "Your services retrieved successfully!",
        data: result,
      });
    } catch (error) {
      console.error("Get my services error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to retrieve your services.",
      });
    }
  },
);

app.get(
  "/api/service-requests/technician",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const technicianEmail = req.user.email;

      const result = await serviceRequests
        .find({ technicianEmail })
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).send({
        success: true,
        message: "Service requests retrieved successfully!",
        data: result,
      });
    } catch (error) {
      console.error("Get technician requests error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to retrieve service requests.",
      });
    }
  },
);




app.patch(
  "/api/service-requests/:id/status",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, finalAmount } = req.body;

      // Validate request ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid request ID.",
        });
      }

      // Allowed statuses
      const allowedStatuses = [
        "accepted",
        "rejected",
        "in-progress",
        "completed",
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).send({
          success: false,
          message: "Invalid request status.",
        });
      }

      // Validate final amount when completing
      if (status === "completed") {
        if (
          finalAmount === undefined ||
          finalAmount === null ||
          finalAmount === "" ||
          !Number.isFinite(Number(finalAmount)) ||
          Number(finalAmount) <= 0
        ) {
          return res.status(400).send({
            success: false,
            message: "Please provide a valid final amount.",
          });
        }
      }

      // Find request belonging to this technician
      const existingRequest = await serviceRequests.findOne({
        _id: new ObjectId(id),
        technicianEmail: req.user.email,
      });

      if (!existingRequest) {
        return res.status(404).send({
          success: false,
          message: "Service request not found.",
        });
      }

      // Only requested requests can be accepted or rejected
      if (
        ["accepted", "rejected"].includes(status) &&
        existingRequest.status !== "requested"
      ) {
        return res.status(400).send({
          success: false,
          message: "This request has already been processed.",
        });
      }

      // Only accepted requests can be started
      if (
        status === "in-progress" &&
        existingRequest.status !== "accepted"
      ) {
        return res.status(400).send({
          success: false,
          message: "Only accepted requests can be started.",
        });
      }

      // Only ongoing jobs can be completed
      if (
        status === "completed" &&
        existingRequest.status !== "in-progress"
      ) {
        return res.status(400).send({
          success: false,
          message: "Only ongoing jobs can be completed.",
        });
      }

      // Prepare update fields
      const updateFields = {
        status,
        updatedAt: new Date(),
      };

      // Save final amount when completing
      if (status === "completed") {
        updateFields.finalAmount = Number(finalAmount);
        updateFields.paymentStatus = "unpaid";
      }

      // Update request
      const result = await serviceRequests.updateOne(
        {
          _id: new ObjectId(id),
          technicianEmail: req.user.email,
          status: existingRequest.status,
        },
        {
          $set: updateFields,
        }
      );

      if (!result.modifiedCount) {
        return res.status(409).send({
          success: false,
          message: "Request status changed. Please refresh.",
        });
      }

      return res.status(200).send({
        success: true,
        message: `Request ${status} successfully!`,
      });
    } catch (error) {
      console.error("Update request status error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to update request status.",
      });
    }
  }
);





// api for customer

//service request APIs for customer



app.post(
  "/api/service-requests",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const {
        serviceId,
        problemDescription,
        customerPhone,
        address,
        preferredDate,
      } = req.body;

      // Validate required fields
      if (
        !serviceId ||
        !problemDescription ||
        !customerPhone ||
        !address ||
        !preferredDate
      ) {
        return res.status(400).send({
          success: false,
          message: "Please provide all required fields.",
        });
      }

      // Validate service ID
      if (!ObjectId.isValid(serviceId)) {
        return res.status(400).send({
          success: false,
          message: "Invalid service ID.",
        });
      }

      // Trim input values
      const trimmedProblem = String(problemDescription).trim();
      const trimmedPhone = String(customerPhone).trim();
      const trimmedAddress = String(address).trim();

      if (trimmedProblem.length < 20) {
        return res.status(400).send({
          success: false,
          message: "Problem description must be at least 20 characters.",
        });
      }

      if (!trimmedPhone || !trimmedAddress) {
        return res.status(400).send({
          success: false,
          message: "Phone number and address cannot be empty.",
        });
      }

      // Validate preferred date (YYYY-MM-DD)
      const datePattern = /^\d{4}-\d{2}-\d{2}$/;

      if (
        typeof preferredDate !== "string" ||
        !datePattern.test(preferredDate)
      ) {
        return res.status(400).send({
          success: false,
          message: "Please provide a valid preferred date.",
        });
      }

      const [year, month, day] = preferredDate.split("-").map(Number);

      const selectedDate = new Date(year, month - 1, day);

      // Check whether the calendar date actually exists
      if (
        selectedDate.getFullYear() !== year ||
        selectedDate.getMonth() !== month - 1 ||
        selectedDate.getDate() !== day
      ) {
        return res.status(400).send({
          success: false,
          message: "Please provide a valid preferred date.",
        });
      }

      // Prevent past dates using server-local calendar date
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      if (selectedDate < today) {
        return res.status(400).send({
          success: false,
          message: "Preferred date cannot be in the past.",
        });
      }

      // Find selected approved and available service
      const service = await services.findOne({
        _id: new ObjectId(serviceId),
        approvalStatus: "approved",
        isAvailable: true,
      });

      if (!service) {
        return res.status(404).send({
          success: false,
          message: "Service not found or unavailable.",
        });
      }

      // Get customer information from verified token
      const customerEmail = req.user.email;
      const customerName = req.user.name;

      if (!customerEmail || !customerName) {
        return res.status(401).send({
          success: false,
          message: "Customer information missing.",
        });
      }

      // Prevent duplicate active requests
      const activeRequest = await serviceRequests.findOne({
        serviceId: service._id,
        customerEmail,
        status: {
          $in: ["requested", "accepted", "in-progress"],
        },
      });

      if (activeRequest) {
        return res.status(409).send({
          success: false,
          message: "You already have an active request for this service.",
        });
      }

      // Create new repair request
      const newRequest = {
        serviceId: service._id,

        serviceTitle: service.title,
        serviceCategory: service.category,
        servicePrice: service.basePrice,
        serviceImage: service.image,

        technicianName: service.technicianName,
        technicianEmail: service.technicianEmail,

        customerName,
        customerEmail,
        customerPhone: trimmedPhone,

        problemDescription: trimmedProblem,
        address: trimmedAddress,
        preferredDate,

        status: "requested",
        paymentStatus: "unpaid",

        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await serviceRequests.insertOne(newRequest);

      return res.status(201).send({
        success: true,
        message: "Repair request submitted successfully!",
        data: {
          _id: result.insertedId,
          ...newRequest,
        },
      });
    } catch (error) {
      console.error("Create service request error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to submit repair request.",
      });
    }
  }
);

// ========================================
// CUSTOMER CANCEL SERVICE REQUEST
// A customer can cancel only their own
// request while its status is "requested".
// ========================================

app.patch(
  "/api/service-requests/:id/cancel",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking ID.",
        });
      }

      const result = await serviceRequests.updateOne(
        {
          _id: new ObjectId(id),
          customerEmail: req.user.email,
          status: "requested",
        },
        {
          $set: {
            status: "cancelled",
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Request not found, or it can no longer be cancelled.",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Repair request cancelled successfully.",
      });
    } catch (error) {
      console.error("Cancel service request error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to cancel repair request.",
      });
    }
  }
);




// Get logged-in customer's bookings

app.get(
  "/api/service-requests/customer",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const customerEmail = req.user.email;

      const bookings = await serviceRequests
        .find({ customerEmail })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Customer repair requests retrieved successfully.",
        data: bookings,
      });
    } catch (error) {
      console.error("Customer repair requests error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve customer repair requests.",
      });
    }
  }
);


// Get logged-in customer's payment history
app.get(
  "/api/payments/customer",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const customerEmail = req.user.email;

      const paymentHistory = await payments
        .find({ customerEmail })
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).json({
        success: true,
        message: "Payment history retrieved successfully.",
        data: paymentHistory,
      });
    } catch (error) {
      console.error("Customer payments error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to retrieve payment history.",
      });
    }
  },
);

// ========================================
// ADMIN DASHBOARD APIs
// All routes require a valid admin JWT
// ========================================

// 1. Admin dashboard overview
app.get("/api/admin/overview", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalTechnicians,
      totalCustomers,
      totalServices,
      pendingServices,
      approvedServices,
      rejectedServices,
      totalBookings,
      pendingBookings,
      completedBookings,
      totalTransactions,
    ] = await Promise.all([
      users.countDocuments({}),
      users.countDocuments({ role: "technician" }),
      users.countDocuments({ role: "customer" }),

      services.countDocuments({}),
      services.countDocuments({ approvalStatus: "pending" }),
      services.countDocuments({ approvalStatus: "approved" }),
      services.countDocuments({ approvalStatus: "rejected" }),

      serviceRequests.countDocuments({}),
      serviceRequests.countDocuments({ status: "pending" }),
      serviceRequests.countDocuments({ status: "completed" }),

      payments.countDocuments({}),
    ]);

    res.status(200).json({
      success: true,
      message: "Admin dashboard overview retrieved successfully.",
      data: {
        totalUsers,
        totalTechnicians,
        totalCustomers,
        totalServices,
        pendingServices,
        approvedServices,
        rejectedServices,
        totalBookings,
        pendingBookings,
        completedBookings,
        totalTransactions,
      },
    });
  } catch (error) {
    console.error("Admin overview error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve admin dashboard overview.",
    });
  }
});

// 2. Get all users
app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await users.find({}).sort({ createdAt: -1 }).toArray();

    res.status(200).json({
      success: true,
      message: "Users retrieved successfully.",
      data: result,
    });
  } catch (error) {
    console.error("Admin users error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve users.",
    });
  }
});

// 3. Get all services
app.get("/api/admin/services", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await services.find({}).sort({ createdAt: -1 }).toArray();

    res.status(200).json({
      success: true,
      message: "Services retrieved successfully.",
      data: result,
    });
  } catch (error) {
    console.error("Admin services error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve services.",
    });
  }
});

// 4. Approve or reject a service
app.patch(
  "/api/admin/services/:id/approval",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { approvalStatus } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      if (!["approved", "rejected"].includes(approvalStatus)) {
        return res.status(400).json({
          success: false,
          message: "Approval status must be approved or rejected.",
        });
      }

      const result = await services.updateOne(
        {
          _id: new ObjectId(id),
          approvalStatus: "pending",
        },
        {
          $set: {
            approvalStatus,
            reviewedAt: new Date(),
          },
        },
      );

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Pending service not found.",
        });
      }

      res.status(200).json({
        success: true,
        message: `Service ${approvalStatus} successfully.`,
      });
    } catch (error) {
      console.error("Service approval error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to update service approval.",
      });
    }
  },
);

// 5. Delete a service
app.delete(
  "/api/admin/services/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      const result = await services.deleteOne({
        _id: new ObjectId(id),
      });

      if (!result.deletedCount) {
        return res.status(404).json({
          success: false,
          message: "Service not found.",
        });
      }

      res.status(200).json({
        success: true,
        message: "Service deleted successfully.",
      });
    } catch (error) {
      console.error("Delete service error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to delete service.",
      });
    }
  },
);

// 6. Get all bookings
app.get("/api/admin/bookings", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await serviceRequests
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      message: "Bookings retrieved successfully.",
      data: result,
    });
  } catch (error) {
    console.error("Admin bookings error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve bookings.",
    });
  }
});

// 7. Get all transactions
app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await payments.find({}).sort({ createdAt: -1 }).toArray();

      res.status(200).json({
        success: true,
        message: "Transactions retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Admin transactions error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to retrieve transactions.",
      });
    }
  },
);


// public service APIs
app.get("/api/services", async (req, res) => {
  try {
    const result = await services
      .find({
        approvalStatus: "approved",
        isAvailable: true,
      })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      message: "Available services retrieved successfully.",
      data: result,
    });
  } catch (error) {
    console.error("Get services error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve services.",
    });
  }
});
// GET individual service details

app.get("/api/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID.",
      });
    }

    const service = await services.findOne({
      _id: new ObjectId(id),
      approvalStatus: "approved",
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found or unavailable.",
      });
    }

    // Get technician profile from users collection
    const technician = await users.findOne(
      {
        email: service.technicianEmail,
        role: "technician",
      },
      {
        projection: {
          name: 1,
          email: 1,
          image: 1,
          area: 1,
          bio: 1,
        },
      }
    );

    res.status(200).json({
      success: true,
      message: "Service details retrieved successfully.",
      data: {
        ...service,
        technician: technician
          ? {
              name: technician.name,
              email: technician.email,
              image: technician.image,
              area: technician.area,
              bio: technician.bio,
            }
          : null,
      },
    });
  } catch (error) {
    console.error("Get service details error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve service details.",
    });
  }
});

// Get latest 6 featured services
app.get("/api/featured-services", async (req, res) => {
  try {
    const featuredServices = await services
      .find({
        approvalStatus: "approved",
        isAvailable: true,
      })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray();

    res.status(200).send({
      success: true,
      message: "Featured services fetched successfully.",
      data: featuredServices,
    });
  } catch (error) {
    console.error("Error fetching featured services:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch featured services.",
    });
  }
});



// ========================================
// CREATE STRIPE CHECKOUT SESSION
// Customer can pay only for their own
// completed and unpaid repair request.
// ========================================

app.post(
  "/api/payments/create-checkout-session",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { bookingId } = req.body;

      if (!bookingId || !ObjectId.isValid(bookingId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking ID.",
        });
      }

      const customerEmail = req.user.email;

      const booking = await serviceRequests.findOne({
        _id: new ObjectId(bookingId),
        customerEmail,
        status: "completed",
        paymentStatus: "unpaid",
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message:
            "Completed unpaid booking not found.",
        });
      }

      const finalAmount = Number(booking.finalAmount);

      if (!Number.isFinite(finalAmount) || finalAmount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid final repair amount.",
        });
      }

      // Reuse an existing open Checkout Session
      if (booking.stripeSessionId) {
        const existingSession = await stripe.checkout.sessions.retrieve(
          booking.stripeSessionId
        );

        if (
          existingSession.status === "open" &&
          existingSession.url
        ) {
          return res.status(200).json({
            success: true,
            message: "Checkout session retrieved successfully.",
            url: existingSession.url,
          });
        }
      }

      const frontendUrl = process.env.CLIENT_URL.replace(/\/$/, "");

      // Create a new Stripe Checkout Session
      const session = await stripe.checkout.sessions.create({
        mode: "payment",

       

        customer_email: booking.customerEmail,

        client_reference_id: booking._id.toString(),

        line_items: [
          {
            price_data: {
              currency: "bdt",
              product_data: {
                name: booking.serviceTitle || "FixMate Repair Service",
                description: `Repair booking #${booking._id}`,
              },
              // BDT uses two decimal places.
              unit_amount: Math.round(finalAmount * 100),
            },
            quantity: 1,
          },
        ],

        metadata: {
          bookingId: booking._id.toString(),
          customerEmail: booking.customerEmail,
        },

        success_url:
          `${frontendUrl}/dashboard/customer/payments?payment=success&session_id={CHECKOUT_SESSION_ID}`,

        cancel_url:
          `${frontendUrl}/dashboard/customer/bookings?payment=cancelled`,
      });

      // Save the Checkout Session ID with the booking
      await serviceRequests.updateOne(
        {
          _id: booking._id,
          customerEmail,
          status: "completed",
          paymentStatus: "unpaid",
        },
        {
          $set: {
            stripeSessionId: session.id,
            updatedAt: new Date(),
          },
        }
      );

      return res.status(200).json({
        success: true,
        message: "Checkout session created successfully.",
        url: session.url,
      });
    } catch (error) {
      console.error("Create Stripe session error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create payment session.",
      });
    }
  }
);





app.post(
  "/api/payments/verify-session",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { sessionId } = req.body;
      const customerEmail = req.user.email;

      if (!sessionId || typeof sessionId !== "string") {
        return res.status(400).json({
          success: false,
          message: "Session ID is required.",
        });
      }

      // Retrieve the session directly from Stripe
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (
        session.status !== "complete" ||
        session.payment_status !== "paid" ||
        session.mode !== "payment"
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment has not been completed.",
        });
      }

      const bookingId = session.metadata?.bookingId;

      if (
        !bookingId ||
        !ObjectId.isValid(bookingId) ||
        session.metadata?.customerEmail !== customerEmail
      ) {
        return res.status(403).json({
          success: false,
          message: "Invalid payment session.",
        });
      }

      const booking = await serviceRequests.findOne({
        _id: new ObjectId(bookingId),
        customerEmail,
        status: "completed",
        stripeSessionId: session.id,
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found for this payment.",
        });
      }

      const expectedAmount = Math.round(
        Number(booking.finalAmount) * 100
      );

      if (
        !Number.isFinite(expectedAmount) ||
        session.amount_total !== expectedAmount ||
        session.currency !== "bdt"
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment amount or currency does not match.",
        });
      }

      const paidAt = session.created
        ? new Date(session.created * 1000)
        : new Date();

      const transactionId =
        typeof session.payment_intent === "string"
          ? session.payment_intent
          : session.payment_intent?.id || session.id;

      // Insert a payment record only once per Stripe session
      await payments.updateOne(
        { stripeSessionId: session.id },
        {
          $setOnInsert: {
            bookingId: booking._id.toString(),
            serviceTitle: booking.serviceTitle,
            customerName: booking.customerName,
            customerEmail: booking.customerEmail,
            technicianName: booking.technicianName,
            technicianEmail: booking.technicianEmail,
            amount: Number(booking.finalAmount),
            currency: "BDT",
            transactionId,
            stripeSessionId: session.id,
            paymentStatus: "paid",
            paymentMethod: "Card",
            paidAt,
            createdAt: new Date(),
          },
        },
        { upsert: true }
      );

      // Update booking payment status
      await serviceRequests.updateOne(
        {
          _id: booking._id,
          customerEmail,
          stripeSessionId: session.id,
          paymentStatus: { $ne: "paid" },
        },
        {
          $set: {
            paymentStatus: "paid",
            paidAt,
            updatedAt: new Date(),
          },
        }
      );

      return res.status(200).json({
        success: true,
        message: "Payment verified successfully.",
        bookingId: booking._id.toString(),
      });
    } catch (error) {
      console.error("Payment verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to verify payment.",
      });
    }
  }
);




app.get("/", (req, res) => {
  res.send({ message: "Welcome to FixMate!" });
});

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
