import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient } from "mongodb";
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
  })
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

// must call this middleware after verifyToken
const verifyCustomer = async (req, res, next) => {
    if (req.user.role !== 'customer') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }
    next();
}

const verifyTechnician = async (req, res, next) => {
    if (req.user.role !== 'technician') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }
    next();
}

const verifyAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }
    next();
}



// users related apis
app.get('/users', async (req, res) => {
    const cursor = users.find({});
    const result = await cursor.toArray();
    res.send(result);
})

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

    const allowedServiceModes = [
      "Home Visit",
      "Shop Drop-off",
    ];

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
app.get("/api/services/my-services", verifyToken, verifyTechnician, async (req, res) => {
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
});



app.get("/", (req, res) => {
  res.send({ message: "Welcome to FixMate!" });
});

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
