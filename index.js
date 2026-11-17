
import express from "express";
import "dotenv/config";
import cors from "cors";
import { MongoClient } from "mongodb";

const app = express();

const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

const mongoUri = process.env.MONGODB_URI;

const client = new MongoClient(mongoUri);

let db;

export async function connectToMongoDB() {
  try {
    await client.connect();

    console.log("You successfully connected to MongoDB!");

    db = client.db("fixmate");

    return db;
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    throw err;
  }
}

app.get("/", (req, res) => {
  res.send({ message: "Welcome to FixMate!" });
});

connectToMongoDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running successfully at port: ${PORT}`);
    });
  })
  .catch((err) => {
    console.log("MongoDB connection failed !!!", err);
    process.exit(1);
  });
