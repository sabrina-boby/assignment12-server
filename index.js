const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const cors = require("cors");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);


const {
  MongoClient,
  ServerApiVersion,
  ObjectId,
  ChangeStream,
} = require("mongodb");

var admin = require("firebase-admin");

var serviceAccount = require("./admin-key.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// const serviceAccount = require("./admin-key.json");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// console.log("Mongo URI:", process.env.MONGODB_URI);

const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log(" ~ verifyFirebaseToken ~ authHeader:", authHeader);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const idToken = authHeader.split(" ")[1];

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.firebaseUser = decodedToken; // You can access user info like uid, email, etc.
    next();
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid token from catch" });
  }
};

async function run() {
  try {
    // await client.connect();
    const db = client.db("assignment12");
    const userCollection = db.collection("users");
    const blogsCollection = db.collection("blog");
    const donationRequests = db.collection("donationRequests");
    const paymentCollection = db.collection("payments");

    const verifyAdmin = async (req, res, next) => {
      const user = await userCollection.findOne({
        email: req.firebaseUser.email,
      });

      if (user.role === "admin") {
        next();
      } else {
        res.status(403).send({ msg: "unauthorized" });
      }
    };

 

    app.get("/get-user-role", verifyFirebaseToken, async (req, res) => {
      const user = await userCollection.findOne({
        email: req.firebaseUser.email,
      });
      res.send({ msg: "ok", role: user.role, status: "active" });
    });

    app.get(
      "/get-users",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const users = await userCollection
          .find({ email: { $ne: req.firebaseUser.email } })
          .toArray();
        res.send(users);
      }
    );

    app.patch(
      "/update-role",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { email, role } = req.body;
        const result = await userCollection.updateOne(
          { email: email },
          {
            $set: { role },
          }
        );

        res.send(result);
      }
    );



    // Registration api*
    app.post("/api/users", async (req, res) => {
      try {
        const {
          name,
          email,
          avatar,
          bloodGroup,
          district,
          upazila,
          password,
          role,
          status,
        } = req.body;

        // Check if user already exists
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }

        const newUser = {
          name,
          email,
          avatar,
          bloodGroup,
          district,
          upazila,
          password,
          role: role || "donor",
          status: status || "active",
          createdAt: new Date(),
        };
        const result = await userCollection.insertOne(newUser);
        res.json({ insertedId: result.insertedId });
        console.log("User created:", result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to create user" });
      }
    });

    // Search API: filter by bloodGroup, district, upazila (optional query params)
    app.get("/api/users/search", async (req, res) => {
      try {
        const { bloodGroup, district, upazila } = req.query;

        const filters = {};

        if (bloodGroup) filters.bloodGroup = bloodGroup;
        if (district) filters.district = district;
        if (upazila) filters.upazila = upazila;

        console.log("log", filters);

        // Native driver uses toArray() to get results as an array
        const users = await userCollection.find(filters).toArray();

        res.json(users);

      } catch (error) {
        console.error("Search API error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
      }
    });


    //deshbord/profile/
    app.get("/api/users/:email", async (req, res) => {
      try {
        const email = req.params.email;
        const user = await userCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json(user); // frontend will get name, avatar, district, etc.
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to fetch user" });
      }
    });

    // PATCH /api/users/:id

    app.patch("/api/users/:id", async (req, res) => {
      const id = req.params.id;
      const update = {};
      if (req.body.status) update.status = req.body.status;
      if (req.body.role) update.role = req.body.role;

      const result = await db
        .collection("users")
        .updateOne({ _id: new ObjectId(id) }, { $set: update });
      res.send(result);
    });

    // GET all users
    app.get("/api/users", async (req, res) => {
      try {
        const users = await db.collection("users").find().toArray();
        res.send(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send({ error: "Internal Server Error" });
      }
    });

    app.patch("/update-profile/:email", async (req, res) => {
      try {
        const { email } = req.params;
        const updatedData = req.body;

        // Email can't be updated
        delete updatedData.email;

        const result = await userCollection.updateOne(
          { email },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({
          message: "Profile updated",
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to update profile" });
      }
    });

    app.post("/", async (req, res) => {
      try {
        const { title, author, image, content } = req.body;
        const newBlog = new Blog({ title, author, image, content });
        await newBlog.save();
        res.status(201).json({ message: "Blog created successfully" });
      } catch (err) {
        res.status(500).json({ error: "Failed to create blog" });
      }
    });



    // ✅ Get donation requests with optional email + status + pagination
    app.get("/api/donation-requests", async (req, res) => {
      try {
        const { email, status = "all", page = 1, limit = 5 } = req.query;

        const query = {};
        if (email) query.requesterEmail = email;
        if (status !== "all") query.status = status;

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const options = {
          skip,
          limit: parseInt(limit),
          sort: { createdAt: -1 },
        };

        const total = await donationRequests.countDocuments(query);
        const requests = await donationRequests.find(query, options).toArray();

        res.send({
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit),
          requests,
        });
      } catch (error) {
        console.error("Error fetching donation requests:", error);
        res.status(500).json({ error: "Failed to fetch donation requests" });
      }
    });





    // Add new blog (status default draft)
    app.post("/api/blogs", async (req, res) => {
      try {
        const blog = req.body;
        blog.createdAt = new Date();
        blog.status = "draft"; // সবসময় ড্রাফট নতুন ব্লগের জন্য
        const result = await blogsCollection.insertOne(blog);
        res.status(201).json(result);
      } catch (err) {
        res.status(500).json({ error: "Failed to add blog" });
      }
    });

    // Get all blogs with optional status filter & search query
    app.get("/api/blogs", async (req, res) => {
      try {
        const { status, search } = req.query;
        const query = {};

        if (status && status !== "all") {
          query.status = status;
        }

        if (search) {
          query.$or = [
            { title: { $regex: search, $options: "i" } },
            { content: { $regex: search, $options: "i" } },
          ];
        }

        const blogs = await blogsCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.json(blogs);
      } catch (err) {
        res.status(500).json({ error: "Failed to fetch blogs" });
      }
    });

    // Get single blog by ID
    app.get("/reed_more/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const blog = await blogsCollection.findOne({ _id: new ObjectId(id) });
        if (!blog) return res.status(404).json({ error: "Blog not found" });
        res.json(blog);
      } catch (err) {
        res.status(500).json({ error: "Failed to fetch blog" });
      }
    });

    // Update blog (edit content, title, image etc.)
    app.put("/api/blogs/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const updateData = req.body;
        delete updateData.createdAt; // createdAt পরিবর্তন নিষেধ

        const result = await blogsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Blog not found" });
        }

        res.json({ message: "Blog updated" });
      } catch (err) {
        res.status(500).json({ error: "Failed to update blog" });
      }
    });

    // Update blog status (publish/unpublish) - admin only (authorization middleware needed)
    app.patch("/api/blogs/:id/status", async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        if (!["draft", "published"].includes(status)) {
          return res.status(400).json({ error: "Invalid status value" });
        }

        const result = await blogsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({ error: "Blog not found or status unchanged" });
        }

        res.json({ message: "Status updated successfully" });
      } catch (err) {
        res.status(500).json({ error: "Failed to update status" });
      }
    });


    // Delete blog by ID - admin only (authorization middleware needed)
    app.delete("/api/blogs/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const result = await blogsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Blog not found" });
        }
        res.json({ message: "Blog deleted" });
      } catch (err) {
        res.status(500).json({ error: "Failed to delete blog" });
      }
    });

    // ✅ Create a donation request
    app.post("/api/donation-requests", async (req, res) => {
      try {
        const result = await donationRequests.insertOne({
          ...req.body,
          status: "pending", // <-- Keep consistent status
          createdAt: new Date(),
        });

        res.status(201).json(result);
      } catch (error) {
        console.error(" Insert failed:", error);
        res.status(500).json({ error: "Failed to create donation request" });
      }
    });

    // ✅ GET only pending donation requests
    app.get("/api/pending-donation-requests", async (req, res) => {
      try {
        const result = await donationRequests
          .find({ status: "pending" })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error(" Error fetching pending donation requests:", error);
        res.status(500).json({ error: "Failed to fetch pending donation requests" });
      }
    });

    // ✅ donation-requests/:id
    app.get('/api/donation-requests/:id', async (req, res) => {
      try {
        const id = req.params.id;

        // ObjectId তে convert করো
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid ID format' });
        }

        const request = await donationRequests.findOne({ _id: new ObjectId(id) });

        if (!request) {
          return res.status(404).json({ message: 'Request not found' });
        }

        res.json(request);
      } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error' });
      }
    });

    //✅ /donation-requests-details page
    app.patch("/api/donation-requests/:id", async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;

      try {
        const result = await donationRequests.updateOne(  // ✅ fix here
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.modifiedCount === 1) {
          res.send({ success: true });
        } else {
          res.status(404).send({ message: "Not found or already updated" });
        }
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // Dashboard admin and volunteer: get donation requests with filter and pagination
    app.get("/api/donation-requests", async (req, res) => {
      try {
        const { email, status = "all", page = 1, limit = 5 } = req.query;

        const filter = {};

        if (email) {
          filter.requesterEmail = email;
        }

        if (status !== "all") {
          filter.status = status; // use directly, since DB values are lowercase
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const total = await donationRequests.countDocuments(filter);
        const requests = await donationRequests
          .find(filter)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.send({
          totalPages: Math.ceil(total / limit),
          currentPage: parseInt(page),
          totalItems: total,
          requests,
        });
      } catch (error) {
        console.error("Error fetching donation requests:", error);
        res.status(500).json({ error: "Failed to fetch donation requests" });
      }
    });


  
    app.post("/create-payment-intent", async (req, res) => {
      const { amount } = req.body;

      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount * 100, // in cents (e.g., 500 = $5.00)
          currency: "usd",
          payment_method_types: ["card"],

        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    //Money or money
    app.post("/api/funding", async (req, res) => {
      try {
        const payment = req.body;

        // Check if name, email, or amount is missing
        if (!payment?.name || !payment?.email || !payment?.amount) {
          return res.status(400).send({ error: "Invalid payment data" });
        }

        const result = await paymentCollection.insertOne(payment);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Internal server error" });
      }
    });


    app.get("/api/funds", async (req, res) => {

      try {
        const result = await paymentCollection.find({}).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Internal server error" });
      }

    })


    /// get all payment
    app.get("/api/funding", async (req, res) => {
      try {
        const result = await paymentCollection.find({}).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Internal server error" });
      }
    });


    console.log("connected");
  } finally {
  }
}

run().catch(console.dir);

// Root route
app.get("/", async (req, res) => {
  res.send("hello");
});

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});

/*
1. authorization
*/
