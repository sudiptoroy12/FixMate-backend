
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
  })
);

app.use(express.json());

// ========================================
// DATABASE CONNECTION
// ========================================

const mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
  throw new Error("MONGODB_URI is not configured.");
}

const client = new MongoClient(mongoUri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    throw err;
  }
}

const connectedClient = await connectToMongoDB();

const database = connectedClient.db("fixmate");

const users = database.collection("user");
const sessions = database.collection("sessions");
const payments = database.collection("payments");
const services = database.collection("services");
const serviceRequests = database.collection("serviceRequests");

// ========================================
// STRIPE CONFIGURATION
// ========================================

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("STRIPE_SECRET_KEY is not configured.");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// FixMate uses USD for all new services and payments.
const CURRENCY = "usd";
const DATABASE_CURRENCY = "USD";

// Minimum service and payment amount: $1.00
const MIN_PRICE_CENTS = 100;
const MAX_PRICE_CENTS = 99999999;

// Convert USD to Stripe cents.
// Example: $10.50 = 1050 cents.
const toUsdCents = (value) => {
  const amount = Number(value);

  if (!Number.isFinite(amount)) {
    return null;
  }

  const cents = Math.round(amount * 100);

  if (
    cents < MIN_PRICE_CENTS ||
    cents > MAX_PRICE_CENTS ||
    Math.abs(amount - cents / 100) > 0.000001
  ) {
    return null;
  }

  return cents;
};

// Create indexes
await payments.createIndex(
  { stripeSessionId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      stripeSessionId: { $type: "string" },
    },
  }
);

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
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

// Customer authorization
const verifyCustomer = async (req, res, next) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden",
    });
  }

  next();
};

// Technician authorization
const verifyTechnician = async (req, res, next) => {
  if (req.user.role !== "technician") {
    return res.status(403).json({
      success: false,
      message: "Forbidden",
    });
  }

  next();
};

// Admin authorization
const verifyAdmin = async (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden",
    });
  }

  next();
};



// ========================================
// TECHNICIAN SERVICE APIs
// ========================================

// Create new service
app.post(
  "/api/services",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
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
        basePrice === undefined ||
        basePrice === null ||
        basePrice === ""
      ) {
        return res.status(400).json({
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

      const allowedServiceModes = [
        "Home Visit",
        "Shop Drop-off",
      ];

      if (!allowedCategories.includes(category)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service category.",
        });
      }

      if (!allowedServiceModes.includes(serviceMode)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service mode.",
        });
      }

      const priceCents = toUsdCents(basePrice);

      if (priceCents === null) {
        return res.status(400).json({
          success: false,
          message:
            "Service price must be at least $1.00 USD and cannot have more than 2 decimal places.",
        });
      }

      const price = priceCents / 100;

      const technicianEmail = req.user.email;
      const technicianName = req.user.name;

      if (!technicianEmail || !technicianName) {
        return res.status(401).json({
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
        currency: DATABASE_CURRENCY,

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

      return res.status(201).json({
        success: true,
        message: "Service created successfully!",
        data: {
          _id: result.insertedId,
          ...newService,
        },
      });
    } catch (error) {
      console.error("Create service error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to create service.",
      });
    }
  }
);

// Get services created by logged-in technician
app.get(
  "/api/services/my-services",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).json({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      const result = await services
        .find({ technicianEmail })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Your services retrieved successfully!",
        data: result,
      });
    } catch (error) {
      console.error("Get my services error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve your services.",
      });
    }
  }
);


// ========================================
// UPDATE TECHNICIAN SERVICE
// ========================================

app.patch(
  "/api/services/:id",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

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
        basePrice === undefined ||
        basePrice === null ||
        basePrice === ""
      ) {
        return res.status(400).json({
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

      const allowedServiceModes = [
        "Home Visit",
        "Shop Drop-off",
      ];

      if (!allowedCategories.includes(category)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service category.",
        });
      }

      if (!allowedServiceModes.includes(serviceMode)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service mode.",
        });
      }

      const trimmedTitle = String(title).trim();
      const trimmedDescription = String(description).trim();
      const trimmedImage = String(image).trim();
      const trimmedDuration = String(estimatedDuration).trim();
      const trimmedArea = String(serviceArea).trim();

      if (
        !trimmedTitle ||
        !trimmedDescription ||
        !trimmedImage ||
        !trimmedDuration ||
        !trimmedArea
      ) {
        return res.status(400).json({
          success: false,
          message: "Fields cannot contain only spaces.",
        });
      }

      const priceCents = toUsdCents(basePrice);

      if (priceCents === null) {
        return res.status(400).json({
          success: false,
          message:
            "Service price must be at least $1.00 USD and cannot have more than 2 decimal places.",
        });
      }

      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).json({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      // Only update the logged-in technician's own service.
      const result = await services.updateOne(
        {
          _id: new ObjectId(id),
          technicianEmail,
        },
        {
          $set: {
            title: trimmedTitle,
            category,
            description: trimmedDescription,
            image: trimmedImage,
            basePrice: priceCents / 100,
            currency: DATABASE_CURRENCY,
            estimatedDuration: trimmedDuration,
            serviceMode,
            serviceArea: trimmedArea,

            // Every edit requires admin approval again.
            approvalStatus: "pending",
            reviewedAt: null,

            updatedAt: new Date(),
          },
        }
      );

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Service not found or you do not own this service.",
        });
      }

      return res.status(200).json({
        success: true,
        message:
          "Service updated successfully! It is now pending admin approval.",
      });
    } catch (error) {
      console.error("Update technician service error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update service.",
      });
    }
  }
);

// ========================================
// DELETE TECHNICIAN SERVICE
// ========================================

app.delete(
  "/api/services/:id",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).json({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      // Delete only the logged-in technician's own service.
      const result = await services.deleteOne({
        _id: new ObjectId(id),
        technicianEmail,
      });

      if (!result.deletedCount) {
        return res.status(404).json({
          success: false,
          message: "Service not found or you do not own this service.",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Service deleted successfully!",
      });
    } catch (error) {
      console.error("Delete technician service error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to delete service.",
      });
    }
  }
);

// ========================================
// TOGGLE TECHNICIAN SERVICE AVAILABILITY
// ========================================

app.patch(
  "/api/services/:id/availability",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isAvailable } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      if (typeof isAvailable !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "isAvailable must be true or false.",
        });
      }

      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).json({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      // Update only the logged-in technician's own service.
      const result = await services.updateOne(
        {
          _id: new ObjectId(id),
          technicianEmail,
        },
        {
          $set: {
            isAvailable,
            updatedAt: new Date(),
          },
        }
      );

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Service not found or you do not own this service.",
        });
      }

      return res.status(200).json({
        success: true,
        message: isAvailable
          ? "Service is now available."
          : "Service is now unavailable.",
        data: {
          isAvailable,
        },
      });
    } catch (error) {
      console.error("Toggle service availability error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update service availability.",
      });
    }
  }
);


// ========================================
// TECHNICIAN PAYMENT / EARNINGS
// ========================================

app.get(
  "/api/payments/technician",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const technicianEmail = req.user.email;

      if (!technicianEmail) {
        return res.status(401).json({
          success: false,
          message: "Technician email not found in token.",
        });
      }

      // Only count successful USD payments
      const result = await payments
        .aggregate([
          {
            $match: {
              technicianEmail,
              currency: "USD",
              paymentStatus: "paid",
            },
          },
          {
            $group: {
              _id: null,
              totalEarnings: {
                $sum: {
                  $convert: {
                    input: "$amount",
                    to: "double",
                    onError: 0,
                    onNull: 0,
                  },
                },
              },
              totalPayments: {
                $sum: 1,
              },
            },
          },
        ])
        .toArray();

      const earnings = result[0] || {
        totalEarnings: 0,
        totalPayments: 0,
      };

      return res.status(200).json({
        success: true,
        message: "Technician earnings retrieved successfully.",
        data: {
          totalEarnings: Number(
            earnings.totalEarnings.toFixed(2)
          ),
          totalPayments: earnings.totalPayments,
          currency: "USD",
        },
      });
    } catch (error) {
      console.error("Technician earnings error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve technician earnings.",
      });
    }
  }
);


// ========================================
// TECHNICIAN SERVICE REQUEST APIs
// ========================================

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

      return res.status(200).json({
        success: true,
        message: "Service requests retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Get technician requests error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve service requests.",
      });
    }
  }
);

// Update technician request status
app.patch(
  "/api/service-requests/:id/status",
  verifyToken,
  verifyTechnician,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, finalAmount } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
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
        return res.status(400).json({
          success: false,
          message: "Invalid request status.",
        });
      }

      let finalAmountCents = null;

      // Validate final repair amount
      if (status === "completed") {
        finalAmountCents = toUsdCents(finalAmount);

        if (finalAmountCents === null) {
          return res.status(400).json({
            success: false,
            message:
              "Final repair amount must be at least $1.00 USD and cannot have more than 2 decimal places.",
          });
        }
      }

      const existingRequest = await serviceRequests.findOne({
        _id: new ObjectId(id),
        technicianEmail: req.user.email,
      });

      if (!existingRequest) {
        return res.status(404).json({
          success: false,
          message: "Service request not found.",
        });
      }

      if (
        ["accepted", "rejected"].includes(status) &&
        existingRequest.status !== "requested"
      ) {
        return res.status(400).json({
          success: false,
          message: "This request has already been processed.",
        });
      }

      if (
        status === "in-progress" &&
        existingRequest.status !== "accepted"
      ) {
        return res.status(400).json({
          success: false,
          message: "Only accepted requests can be started.",
        });
      }

      if (
        status === "completed" &&
        existingRequest.status !== "in-progress"
      ) {
        return res.status(400).json({
          success: false,
          message: "Only ongoing jobs can be completed.",
        });
      }

      // Do not allow an old non-USD booking to be completed.
      if (
        status === "completed" &&
        existingRequest.currency !== DATABASE_CURRENCY
      ) {
        return res.status(400).json({
          success: false,
          message:
            "This booking does not use USD. Please review its currency before completing it.",
        });
      }

      const updateFields = {
        status,
        updatedAt: new Date(),
      };

      if (status === "completed") {
        updateFields.finalAmount = finalAmountCents / 100;
        updateFields.currency = DATABASE_CURRENCY;
        updateFields.paymentStatus = "unpaid";
      }

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
        return res.status(409).json({
          success: false,
          message: "Request status changed. Please refresh.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Request ${status} successfully!`,
      });
    } catch (error) {
      console.error("Update request status error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update request status.",
      });
    }
  }
);

// ========================================
// CUSTOMER SERVICE REQUEST APIs
// ========================================

// Customer creates repair request
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

      if (
        !serviceId ||
        !problemDescription ||
        !customerPhone ||
        !address ||
        !preferredDate
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide all required fields.",
        });
      }

      if (!ObjectId.isValid(serviceId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      const trimmedProblem = String(problemDescription).trim();
      const trimmedPhone = String(customerPhone).trim();
      const trimmedAddress = String(address).trim();

      if (trimmedProblem.length < 20) {
        return res.status(400).json({
          success: false,
          message:
            "Problem description must be at least 20 characters.",
        });
      }

      if (!trimmedPhone || !trimmedAddress) {
        return res.status(400).json({
          success: false,
          message: "Phone number and address cannot be empty.",
        });
      }

      // Validate date
      const datePattern = /^\d{4}-\d{2}-\d{2}$/;

      if (
        typeof preferredDate !== "string" ||
        !datePattern.test(preferredDate)
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide a valid preferred date.",
        });
      }

      const [year, month, day] = preferredDate.split("-").map(Number);

      const selectedDate = new Date(year, month - 1, day);

      if (
        selectedDate.getFullYear() !== year ||
        selectedDate.getMonth() !== month - 1 ||
        selectedDate.getDate() !== day
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide a valid preferred date.",
        });
      }

      const today = new Date();
      today.setHours(0, 0, 0, 0);

      if (selectedDate < today) {
        return res.status(400).json({
          success: false,
          message: "Preferred date cannot be in the past.",
        });
      }

      const service = await services.findOne({
        _id: new ObjectId(serviceId),
        approvalStatus: "approved",
        isAvailable: true,
      });

      if (!service) {
        return res.status(404).json({
          success: false,
          message: "Service not found or unavailable.",
        });
      }

      // Do not interpret old BDT services as USD.
      if (service.currency !== DATABASE_CURRENCY) {
        return res.status(409).json({
          success: false,
          message:
            "This service has not been migrated to USD pricing. Please contact the administrator.",
        });
      }

      const servicePriceCents = toUsdCents(service.basePrice);

      if (servicePriceCents === null) {
        return res.status(400).json({
          success: false,
          message: "This service has an invalid USD price.",
        });
      }

      const customerEmail = req.user.email;
      const customerName = req.user.name;

      if (!customerEmail || !customerName) {
        return res.status(401).json({
          success: false,
          message: "Customer information missing.",
        });
      }

      const activeRequest = await serviceRequests.findOne({
        serviceId: service._id,
        customerEmail,
        status: {
          $in: ["requested", "accepted", "in-progress"],
        },
      });

      if (activeRequest) {
        return res.status(409).json({
          success: false,
          message:
            "You already have an active request for this service.",
        });
      }

      const newRequest = {
        serviceId: service._id,

        serviceTitle: service.title,
        serviceCategory: service.category,
        servicePrice: servicePriceCents / 100,
        serviceImage: service.image,

        currency: DATABASE_CURRENCY,

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

      return res.status(201).json({
        success: true,
        message: "Repair request submitted successfully!",
        data: {
          _id: result.insertedId,
          ...newRequest,
        },
      });
    } catch (error) {
      console.error("Create service request error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to submit repair request.",
      });
    }
  }
);

// ========================================
// CUSTOMER CANCEL SERVICE REQUEST
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

// Get customer's bookings
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
        message:
          "Customer repair requests retrieved successfully.",
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

// ========================================
// CUSTOMER PAYMENT HISTORY
// ========================================

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

      return res.status(200).json({
        success: true,
        message: "Payment history retrieved successfully.",
        data: paymentHistory,
      });
    } catch (error) {
      console.error("Customer payments error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve payment history.",
      });
    }
  }
);

// ========================================
// ADMIN DASHBOARD APIs
// ========================================

// Admin overview
app.get(
  "/api/admin/overview",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
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

      return res.status(200).json({
        success: true,
        message:
          "Admin dashboard overview retrieved successfully.",
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

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve admin dashboard overview.",
      });
    }
  }
);



// Get all users
app.get(
  "/api/admin/users",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await users
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Users retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Admin users error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve users.",
      });
    }
  }
);
// Update a user's role (Admin only)
app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      const allowedRoles = ["customer", "technician", "admin"];

      // Validate user ID
      if (!id || id.length > 100) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID.",
        });
      }

      // Validate role
      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role. Allowed roles: customer, technician, admin.",
        });
      }

      // Support MongoDB ObjectId and string-based IDs
      const userFilter = ObjectId.isValid(id)
        ? {
            $or: [
              { _id: new ObjectId(id) },
              { _id: id },
            ],
          }
        : { _id: id };

      const targetUser = await users.findOne(userFilter);

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: "User not found.",
        });
      }

      // Prevent an admin from changing their own role
      if (
        (req.user.email &&
          targetUser.email?.toLowerCase() === req.user.email.toLowerCase()) ||
        (req.user.sub &&
          String(targetUser._id) === String(req.user.sub))
      ) {
        return res.status(400).json({
          success: false,
          message: "You cannot change your own role.",
        });
      }

      // Prevent removing the last admin
      if (targetUser.role === "admin" && role !== "admin") {
        const adminCount = await users.countDocuments({
          role: "admin",
        });

        if (adminCount <= 1) {
          return res.status(400).json({
            success: false,
            message: "You cannot remove the last admin.",
          });
        }
      }

      // Update role
      await users.updateOne(userFilter, {
        $set: {
          role,
          updatedAt: new Date(),
        },
      });

      return res.status(200).json({
        success: true,
        message: "User role updated successfully.",
        data: {
          _id: targetUser._id,
          name: targetUser.name,
          email: targetUser.email,
          role,
        },
      });
    } catch (error) {
      console.error("Update user role error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update user role.",
      });
    }
  }
);

// Get all services
app.get(
  "/api/admin/services",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await services
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Services retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Admin services error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve services.",
      });
    }
  }
);

// Approve or reject service
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
          message:
            "Approval status must be approved or rejected.",
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
        }
      );

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Pending service not found.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Service ${approvalStatus} successfully.`,
      });
    } catch (error) {
      console.error("Service approval error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update service approval.",
      });
    }
  }
);

// Delete a service
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

      return res.status(200).json({
        success: true,
        message: "Service deleted successfully.",
      });
    } catch (error) {
      console.error("Delete service error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to delete service.",
      });
    }
  }
);

// Get all bookings
app.get(
  "/api/admin/bookings",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await serviceRequests
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Bookings retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Admin bookings error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve bookings.",
      });
    }
  }
);

// ========================================
// ADMIN UPDATE BOOKING STATUS
// ========================================

app.patch(
  "/api/admin/bookings/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, finalAmount } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking ID.",
        });
      }

      const allowedStatuses = [
        "accepted",
        "rejected",
        "in-progress",
        "completed",
        "cancelled",
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking status.",
        });
      }

      const booking = await serviceRequests.findOne({
        _id: new ObjectId(id),
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found.",
        });
      }

      // Only allow valid status transitions.
      const allowedTransitions = {
        requested: ["accepted", "rejected", "cancelled"],
        accepted: ["in-progress", "cancelled"],
        "in-progress": ["completed", "cancelled"],
        completed: [],
        rejected: [],
        cancelled: [],
      };

      if (!allowedTransitions[booking.status]?.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Cannot change booking from ${booking.status} to ${status}.`,
        });
      }

      const updateFields = {
        status,
        updatedAt: new Date(),
      };

      // Validate final repair amount when completing a booking.
      if (status === "completed") {
        if (booking.currency !== DATABASE_CURRENCY) {
          return res.status(400).json({
            success: false,
            message: "Only USD bookings can be completed.",
          });
        }

        const amountCents = toUsdCents(finalAmount);

        if (amountCents === null) {
          return res.status(400).json({
            success: false,
            message:
              "Final repair amount must be at least $1.00 USD with a maximum of 2 decimal places.",
          });
        }

        updateFields.finalAmount = amountCents / 100;
        updateFields.paymentStatus = "unpaid";
      }

      const result = await serviceRequests.updateOne(
        {
          _id: new ObjectId(id),
          status: booking.status,
          paymentStatus: { $ne: "paid" },
        },
        {
          $set: updateFields,
        }
      );

      if (!result.modifiedCount) {
        return res.status(409).json({
          success: false,
          message:
            "Booking was changed or already paid. Please refresh.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Booking ${status} successfully.`,
      });
    } catch (error) {
      console.error("Admin booking status update error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update booking status.",
      });
    }
  }
);


// Get all transactions
app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await payments
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Transactions retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Admin transactions error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve transactions.",
      });
    }
  }
);

// ========================================
// PUBLIC SERVICE APIs
// ========================================

// Get all approved services
app.get("/api/services", async (req, res) => {
  try {
    const result = await services
      .find({
        approvalStatus: "approved",
        isAvailable: true,
      })
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Available services retrieved successfully.",
      data: result,
    });
  } catch (error) {
    console.error("Get services error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to retrieve services.",
    });
  }
});

// Get individual service details
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

    return res.status(200).json({
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

    return res.status(500).json({
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

    return res.status(200).json({
      success: true,
      message: "Featured services fetched successfully.",
      data: featuredServices,
    });
  } catch (error) {
    console.error("Error fetching featured services:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch featured services.",
    });
  }
});

// ========================================
// STRIPE CHECKOUT SESSION
// ========================================

// Customer can pay only for their own
// completed and unpaid repair request.

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
          message: "Completed unpaid booking not found.",
        });
      }

      // Only USD bookings can be paid through this endpoint.
      if (booking.currency !== DATABASE_CURRENCY) {
        return res.status(400).json({
          success: false,
          message:
            "This booking does not use USD. Please contact support.",
        });
      }

      const finalAmountCents = toUsdCents(booking.finalAmount);

      if (finalAmountCents === null) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid final repair amount. Minimum payment is $1.00 USD.",
        });
      }

      // Reuse an existing open USD Checkout Session.
      if (booking.stripeSessionId) {
        const existingSession =
          await stripe.checkout.sessions.retrieve(
            booking.stripeSessionId
          );

        if (
          existingSession.status === "open" &&
          existingSession.currency === CURRENCY &&
          existingSession.url
        ) {
          return res.status(200).json({
            success: true,
            message: "Checkout session retrieved successfully.",
            url: existingSession.url,
          });
        }

        // Expire an old open session with a different currency.
        if (existingSession.status === "open") {
          await stripe.checkout.sessions.expire(
            existingSession.id
          );
        }
      }

      const frontendUrl = process.env.CLIENT_URL.replace(/\/$/, "");

      if (!frontendUrl) {
        throw new Error("CLIENT_URL is not configured.");
      }

      const session = await stripe.checkout.sessions.create({
        mode: "payment",

        customer_email: booking.customerEmail,

        client_reference_id: booking._id.toString(),

        line_items: [
          {
            price_data: {
              currency: CURRENCY,
              product_data: {
                name: booking.serviceTitle || "FixMate Repair Service",
                description: `Repair booking #${booking._id}`,
              },
              unit_amount: finalAmountCents,
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

// ========================================
// VERIFY STRIPE CHECKOUT SESSION
// ========================================

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

      const session =
        await stripe.checkout.sessions.retrieve(sessionId);

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

      const expectedAmount = toUsdCents(booking.finalAmount);

      if (
        booking.currency !== DATABASE_CURRENCY ||
        expectedAmount === null ||
        session.amount_total !== expectedAmount ||
        session.currency !== CURRENCY ||
        session.client_reference_id !== booking._id.toString()
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

      // Insert payment record only once per Stripe session.
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
            currency: DATABASE_CURRENCY,

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

      // Update booking payment status.
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

// ========================================
// SERVER STATUS
// ========================================

app.get("/", (req, res) => {
  res.send({
    message: "Welcome to FixMate!",
    currency: DATABASE_CURRENCY,
  });
});

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
