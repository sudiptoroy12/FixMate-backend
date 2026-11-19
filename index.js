import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

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

app.post(
  "/api/service-requests",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const {
        serviceId,
        deviceName,
        problemDescription,
        customerPhone,
        address,
        preferredDate,
        preferredTime,
      } = req.body;

      if (
        !serviceId ||
        !deviceName ||
        !problemDescription ||
        !customerPhone ||
        !address ||
        !preferredDate ||
        !preferredTime
      ) {
        return res.status(400).send({
          success: false,
          message: "Please provide all required fields.",
        });
      }

      if (!ObjectId.isValid(serviceId)) {
        return res.status(400).send({
          success: false,
          message: "Invalid service ID.",
        });
      }

      // Find the selected service
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
        customerPhone,

        deviceName: String(deviceName).trim(),
        problemDescription: String(problemDescription).trim(),

        address: String(address).trim(),
        preferredDate,
        preferredTime,

        status: "pending",

        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await serviceRequests.insertOne(newRequest);

      res.status(201).send({
        success: true,
        message: "Service request submitted successfully!",
        data: {
          _id: result.insertedId,
          ...newRequest,
        },
      });
    } catch (error) {
      console.error("Create service request error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to submit service request.",
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
      const { status } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid request ID.",
        });
      }

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

      // Only pending requests can be accepted or rejected.
      if (
        ["accepted", "rejected"].includes(status) &&
        existingRequest.status !== "pending"
      ) {
        return res.status(400).send({
          success: false,
          message: "This request has already been processed.",
        });
      }

      // Validate job progress
      if (status === "in-progress" && existingRequest.status !== "accepted") {
        return res.status(400).send({
          success: false,
          message: "Only accepted requests can be started.",
        });
      }

      if (status === "completed" && existingRequest.status !== "in-progress") {
        return res.status(400).send({
          success: false,
          message: "Only ongoing jobs can be completed.",
        });
      }

      const result = await serviceRequests.updateOne(
        {
          _id: new ObjectId(id),
          technicianEmail: req.user.email,
          status: existingRequest.status,
        },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        },
      );

      if (!result.modifiedCount) {
        return res.status(409).send({
          success: false,
          message: "Request status changed. Please refresh.",
        });
      }

      res.status(200).send({
        success: true,
        message: `Request ${status} successfully!`,
      });
    } catch (error) {
      console.error("Update request status error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to update request status.",
      });
    }
  },
);

// api for customer

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

      res.status(200).json({
        success: true,
        message: "Customer bookings retrieved successfully.",
        data: bookings,
      });
    } catch (error) {
      console.error("Customer bookings error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to retrieve customer bookings.",
      });
    }
  },
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

app.get("/", (req, res) => {
  res.send({ message: "Welcome to FixMate!" });
});

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
