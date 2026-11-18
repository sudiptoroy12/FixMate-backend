import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();

const PORT = process.env.PORT || 8000;

app.use(cors());
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


app.get("/", (req, res) => {
  res.send({ message: "Welcome to FixMate!" });
});

app.listen(PORT, () => {
  console.log(`Server is running successfully at port: ${PORT}`);
});

export default app;
