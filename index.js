
import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

// ========================================
// 1. EXPRESS CONFIGURATION
// ========================================

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

// ========================================
// 2. DATABASE CONNECTION
// ========================================

const mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
  throw new Error("MONGODB_URI is not configured.");
}

const client = new MongoClient(mongoUri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");
    return client;
  } catch (error) {
    console.error("MongoDB connection error:", error);
    throw error;
  }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("fixmate");

const users = database.collection("user");
const payments = database.collection("payments");
const services = database.collection("services");
const serviceRequests = database.collection("serviceRequests");

// ========================================
// 3. STRIPE CONFIGURATION
// ========================================

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("STRIPE_SECRET_KEY is not configured.");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const CURRENCY = "usd";
const DATABASE_CURRENCY = "USD";

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

// Create a unique index to prevent duplicate payment records.
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
// 4. AUTHENTICATION MIDDLEWARE
// ========================================

if (!process.env.CLIENT_URL) {
  throw new Error("CLIENT_URL is not configured.");
}

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
);

// Verify JWT token.
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

// Customer authorization.
const verifyCustomer = async (req, res, next) => {
  if (req.user.role !== "customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden. Customer access only.",
    });
  }

  next();
};

// Technician authorization.
const verifyTechnician = async (req, res, next) => {
  if (req.user.role !== "technician") {
    return res.status(403).json({
      success: false,
      message: "Forbidden. Technician access only.",
    });
  }

  next();
};

// Admin authorization.
const verifyAdmin = async (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden. Admin access only.",
    });
  }

  next();
};

// ========================================
// 5. STRIPE WEBHOOK
// IMPORTANT: Must be before express.json()
// ========================================

app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("STRIPE_WEBHOOK_SECRET is not configured.");
      return res.status(500).send("Webhook configuration error.");
    }

    const signature = req.headers["stripe-signature"];

    if (!signature) {
      return res.status(400).send("Missing Stripe signature.");
    }

    let event;

    // 1. Verify Stripe webhook signature.
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        webhookSecret
      );
    } catch (error) {
      console.error("Webhook signature verification failed:", error.message);
      return res.status(400).send("Invalid webhook signature.");
    }

    try {
      // 2. Handle successful Checkout payments only.
      if (
        event.type !== "checkout.session.completed" &&
        event.type !== "checkout.session.async_payment_succeeded"
      ) {
        return res.status(200).json({
          received: true,
          message: "Event ignored.",
        });
      }

      const session = event.data.object;

      // 3. Confirm payment actually succeeded.
      if (
        session.status !== "complete" ||
        session.payment_status !== "paid" ||
        session.mode !== "payment"
      ) {
        return res.status(200).json({
          received: true,
          message: "Payment is not completed yet.",
        });
      }

      // 4. Get booking information from Stripe metadata.
      const { bookingId, customerEmail } = session.metadata || {};

      if (!bookingId || !customerEmail) {
        console.error("Missing booking metadata:", session.id);

        return res.status(400).json({
          received: false,
          message: "Missing booking metadata.",
        });
      }

      if (!ObjectId.isValid(bookingId)) {
        return res.status(400).json({
          received: false,
          message: "Invalid booking ID.",
        });
      }

      // 5. Find the correct booking.
      const booking = await serviceRequests.findOne({
        _id: new ObjectId(bookingId),
        customerEmail,
        stripeSessionId: session.id,
      });

      if (!booking) {
        console.error("Booking not found for Stripe session:", session.id);

        return res.status(404).json({
          received: false,
          message: "Booking not found.",
        });
      }

      // 6. Validate booking ownership and status.
      const bookingEmail = String(
        booking.customerEmail || ""
      ).toLowerCase();

      const metadataEmail = String(customerEmail || "").toLowerCase();

      if (
        booking.status !== "completed" ||
        booking.currency !== DATABASE_CURRENCY ||
        session.client_reference_id !== booking._id.toString() ||
        !bookingEmail ||
        bookingEmail !== metadataEmail
      ) {
        return res.status(400).json({
          received: false,
          message: "Booking validation failed.",
        });
      }

      // 7. Validate payment amount and currency using database values.
      const expectedAmount = toUsdCents(booking.finalAmount);

      if (
        expectedAmount === null ||
        session.amount_total !== expectedAmount ||
        session.currency !== CURRENCY
      ) {
        console.error("Stripe payment amount mismatch:", {
          sessionId: session.id,
          expectedAmount,
          receivedAmount: session.amount_total,
          receivedCurrency: session.currency,
        });

        return res.status(400).json({
          received: false,
          message: "Payment amount or currency mismatch.",
        });
      }

      // 8. Get Stripe PaymentIntent ID.
      const paymentIntentId =
        typeof session.payment_intent === "string"
          ? session.payment_intent
          : session.payment_intent?.id;

      const paidAt = session.created
        ? new Date(session.created * 1000)
        : new Date();

      // 9. Save payment only once.
      // Unique index + $setOnInsert prevents duplicate payment records.
      await payments.updateOne(
        {
          stripeSessionId: session.id,
        },
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

            transactionId: paymentIntentId || session.id,
            stripeSessionId: session.id,

            paymentStatus: "paid",
            paymentMethod: "Card",

            paidAt,
            createdAt: new Date(),
          },
        },
        {
          upsert: true,
        }
      );

      // 10. Update booking payment status.
      await serviceRequests.updateOne(
        {
          _id: booking._id,
          stripeSessionId: session.id,
        },
        {
          $set: {
            paymentStatus: "paid",
            paidAt,
            stripePaymentIntentId: paymentIntentId || null,
          },
        }
      );

      console.log(
        `Payment successfully processed for booking ${booking._id}`
      );

      return res.status(200).json({
        received: true,
        message: "Payment processed successfully.",
      });
    } catch (error) {
      console.error("Stripe webhook processing error:", error);

      // Return 500 so Stripe can retry.
      return res.status(500).json({
        received: false,
        message: "Webhook processing failed.",
      });
    }
  }
);

// ========================================
// 6. JSON BODY MIDDLEWARE
// Must be after the Stripe webhook.
// ========================================

app.use(express.json());

// ========================================
// 7. PUBLIC SERVICE APIs
// ========================================

// Get all approved and available services.
app.get("/api/services", async (req, res) => {
  try {
    const {
      search = "",
      category = "",
      serviceMode = "",
      sort = "newest",
    } = req.query;

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

    if (category && !allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid category.",
      });
    }

    if (
      serviceMode &&
      !allowedServiceModes.includes(serviceMode)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid service mode.",
      });
    }

    const sortOptions = {
      "price-asc": { basePrice: 1 },
      "price-desc": { basePrice: -1 },
      newest: { createdAt: -1 },
    };

    if (!sortOptions[sort]) {
      return res.status(400).json({
        success: false,
        message: "Invalid sorting option.",
      });
    }

    const escapedSearch = String(search)
      .trim()
      .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const query = {
      approvalStatus: "approved",
      isAvailable: true,
    };

    if (category) {
      query.category = category;
    }

    if (serviceMode) {
      query.serviceMode = serviceMode;
    }

    if (escapedSearch) {
      query.$or = [
        {
          title: {
            $regex: escapedSearch,
            $options: "i",
          },
        },
        {
          category: {
            $regex: escapedSearch,
            $options: "i",
          },
        },
      ];
    }

    const result = await services
      .find(query)
      .sort(sortOptions[sort])
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Services retrieved successfully.",
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

// Get latest 6 featured services.
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
// 8. TECHNICIAN SERVICE APIs
// ========================================

// Get logged-in technician's own services.
// IMPORTANT: This static route must be before /api/services/:id.
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
        message: "Your services retrieved successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Get technician services error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve your services.",
      });
    }
  }
);

// Create new service.
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

        basePrice: priceCents / 100,
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

// Update technician's own service.
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

            // Edited services require admin approval again.
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

// Delete technician's own service.
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
      console.error("Delete service error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to delete service.",
      });
    }
  }
);

// Toggle technician service availability.
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

// Get individual approved service details.
// Keep this dynamic GET route after /api/services/my-services.
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

// ========================================
// 9. CUSTOMER SERVICE REQUEST APIs
// ========================================

// Customer creates a repair request.
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
          message: "Problem description must be at least 20 characters.",
        });
      }

      if (!trimmedPhone || !trimmedAddress) {
        return res.status(400).json({
          success: false,
          message: "Phone number and address cannot be empty.",
        });
      }

      // Validate preferred date.
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

      // Prevent duplicate active requests for the same service.
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
          message: "You already have an active request for this service.",
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

// Customer cancels a requested booking.
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

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Request not found, or it can no longer be cancelled.",
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

// Get customer's bookings.
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

// ========================================
// 10. TECHNICIAN SERVICE REQUEST APIs
// ========================================

// Get technician's assigned service requests.
app.get(
  "/api/service-requests/technician",
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

// Only the assigned technician can update a request's status.
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

      // Ownership check: only the assigned technician can access this request.
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

      // requested -> accepted or rejected.
      if (
        ["accepted", "rejected"].includes(status) &&
        existingRequest.status !== "requested"
      ) {
        return res.status(400).json({
          success: false,
          message: "This request has already been processed.",
        });
      }

      // accepted -> in-progress.
      if (
        status === "in-progress" &&
        existingRequest.status !== "accepted"
      ) {
        return res.status(400).json({
          success: false,
          message: "Only accepted requests can be started.",
        });
      }

      // in-progress -> completed.
      if (
        status === "completed" &&
        existingRequest.status !== "in-progress"
      ) {
        return res.status(400).json({
          success: false,
          message: "Only ongoing jobs can be completed.",
        });
      }

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

      // Compare existing status to prevent concurrent status updates.
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
// 11. CUSTOMER PAYMENT APIs
// ========================================

// Get customer's payment history.
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

// Create Stripe Checkout Session.
// Customer can pay only for their own completed and unpaid booking.
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

      if (booking.currency !== DATABASE_CURRENCY) {
        return res.status(400).json({
          success: false,
          message: "This booking does not use USD. Please contact support.",
        });
      }

      const finalAmountCents = toUsdCents(booking.finalAmount);

      if (finalAmountCents === null) {
        return res.status(400).json({
          success: false,
          message: "Invalid final repair amount. Minimum payment is $1.00 USD.",
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

        if (existingSession.status === "open") {
          await stripe.checkout.sessions.expire(existingSession.id);
        }
      }

      const frontendUrl = process.env.CLIENT_URL?.replace(/\/$/, "");

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
          `${frontendUrl}/dashboard/customer/payments/success?payment=success&session_id={CHECKOUT_SESSION_ID}`,

        cancel_url:
          `${frontendUrl}/dashboard/customer/payments/cancel?payment=cancelled`,
      });

      // Save the Stripe session ID to the booking.
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

// Verify Stripe Checkout Session.
// This is the frontend success-page verification endpoint.
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

      // 1. Retrieve Stripe session.
      const session =
        await stripe.checkout.sessions.retrieve(sessionId);

      // 2. Verify Stripe payment status.
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

      // 3. Validate metadata and customer ownership.
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

      // 4. Find customer's completed booking.
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

      // 5. Validate amount and currency.
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

      // 6. Validate Stripe customer email if available.
      const stripeCustomerEmail =
        session.customer_details?.email ||
        session.customer_email;

      if (
        stripeCustomerEmail &&
        stripeCustomerEmail.toLowerCase() !== customerEmail.toLowerCase()
      ) {
        return res.status(403).json({
          success: false,
          message: "Payment customer email does not match.",
        });
      }

      // 7. Get payment information.
      const paidAt = session.created
        ? new Date(session.created * 1000)
        : new Date();

      const transactionId =
        typeof session.payment_intent === "string"
          ? session.payment_intent
          : session.payment_intent?.id || session.id;

      // 8. Insert payment only once per Stripe session.
      await payments.updateOne(
        {
          stripeSessionId: session.id,
        },
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
        {
          upsert: true,
        }
      );

      // 9. Update booking payment status.
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
        data: {
          bookingId: booking._id.toString(),
          serviceTitle: booking.serviceTitle,
          amount: Number(booking.finalAmount),
          currency: DATABASE_CURRENCY,
          transactionId,
          paidAt,
        },
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
// 12. TECHNICIAN EARNINGS
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

      const result = await payments
        .aggregate([
          {
            $match: {
              technicianEmail,
              currency: DATABASE_CURRENCY,
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
          totalEarnings: Number(earnings.totalEarnings.toFixed(2)),
          totalPayments: earnings.totalPayments,
          currency: DATABASE_CURRENCY,
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
// 13. ADMIN DASHBOARD APIs
// ========================================

// Admin overview.
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
        // New bookings use "requested", not "pending".
        serviceRequests.countDocuments({ status: "requested" }),
        serviceRequests.countDocuments({ status: "completed" }),

        payments.countDocuments({}),
      ]);

      return res.status(200).json({
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

      return res.status(500).json({
        success: false,
        message: "Failed to retrieve admin dashboard overview.",
      });
    }
  }
);

// Get all users.
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

// Update a user's role.
app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      const allowedRoles = ["customer", "technician", "admin"];

      if (!id || id.length > 100) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID.",
        });
      }

      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role. Allowed roles: customer, technician, admin.",
        });
      }

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

      // Prevent admin from changing their own role.
      if (
        (req.user.email &&
          targetUser.email?.toLowerCase() === req.user.email.toLowerCase()) ||
        (req.user.sub &&
          String(targetUser._id) === String(req.user.sub))
      ) {
        return res.status(403).json({
          success: false,
          message: "You cannot change your own role.",
        });
      }

      // Prevent removing the last admin.
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

// Get all services for admin.
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

// Approve or reject service.
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

// Delete a service.
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

// Get all bookings for admin.
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


app.patch(
  "/api/admin/bookings/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, finalAmount } = req.body;

      // 1. Validate booking ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking ID.",
        });
      }

      // 2. Validate requested status
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

      // 3. Find existing booking
      const booking = await serviceRequests.findOne({
        _id: new ObjectId(id),
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found.",
        });
      }

      // 4. Prevent modifying paid bookings
      if (booking.paymentStatus === "paid") {
        return res.status(400).json({
          success: false,
          message: "Paid bookings cannot be modified.",
        });
      }

      // 5. Validate status transitions
      const allowedTransitions = {
        requested: ["accepted", "rejected", "cancelled"],
        accepted: ["in-progress", "cancelled"],
        "in-progress": ["completed", "cancelled"],
        completed: [],
        rejected: [],
        cancelled: [],
      };

      const currentStatus = booking.status;

      if (
        !allowedTransitions[currentStatus] ||
        !allowedTransitions[currentStatus].includes(status)
      ) {
        return res.status(400).json({
          success: false,
          message: `Cannot change booking from ${currentStatus} to ${status}.`,
        });
      }

      // 6. Validate final repair amount
      const updateData = {
        status,
        updatedAt: new Date(),
      };

      if (status === "completed") {
        if (
          typeof finalAmount !== "number" ||
          !Number.isFinite(finalAmount) ||
          finalAmount < 1 ||
          Math.round(finalAmount * 100) / 100 !== finalAmount
        ) {
          return res.status(400).json({
            success: false,
            message:
              "Final repair amount must be at least $1.00 USD with a maximum of 2 decimal places.",
          });
        }

        if (booking.currency !== "USD") {
          return res.status(400).json({
            success: false,
            message: "Only USD bookings can be completed.",
          });
        }

        updateData.finalAmount = finalAmount;
        updateData.paymentStatus = "unpaid";
      }

      // 7. Update booking
      const result = await serviceRequests.updateOne(
        {
          _id: new ObjectId(id),
          status: currentStatus,
          paymentStatus: { $ne: "paid" },
        },
        {
          $set: updateData,
        }
      );

      if (result.modifiedCount === 0) {
        return res.status(409).json({
          success: false,
          message:
            "Booking was modified by another request. Please refresh and try again.",
        });
      }

      // 8. Return updated booking
      const updatedBooking = await serviceRequests.findOne({
        _id: new ObjectId(id),
      });

      return res.status(200).json({
        success: true,
        message: "Booking status updated successfully.",
        data: updatedBooking,
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


// Get all transactions for admin.
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
// 14. SERVER STATUS
// ========================================

app.get("/", (req, res) => {
  res.status(200).json({
    message: "Welcome to FixMate!",
  });
});

// ========================================
// 15. START SERVER
// ========================================

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
