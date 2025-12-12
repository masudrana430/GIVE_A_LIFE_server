// server.js
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
require("dotenv").config();

const serviceAccount = require("./sarviceKey.json");

const app = express();
const port = process.env.PORT || 3000;

// CORS
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://give-a-life.netlify.app"
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// Firebase Admin init
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.3hpwj74.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);


// ===== JWT Middleware =====
const verifyToken = async (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({ message: "Unauthorized. Token missing." });
  }

  const token = authorization.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.decodedUser = decoded; // decoded.email, uid, etc.
    next();
  } catch (error) {
    console.error("verifyToken error:", error);
    return res.status(401).send({ message: "Unauthorized. Invalid token." });
  }
};

async function run() {
  try {
    // await client.connect();
        // console.log("Connected to MongoDB");

    const db = client.db("BloodDonationDB");
    const Users = db.collection("users");
    const DonationRequests = db.collection("donationRequests");
    const Funds = db.collection("funds");
    const Issues = db.collection("Issues");
    const MessagesCollection = db.collection("messages");

    // Helpers: role middlewares
    const verifyAdmin = async (req, res, next) => {
      const email = req.decodedUser?.email;
      if (!email) return res.status(401).send({ message: "Unauthorized." });

      const user = await Users.findOne({ email });
      if (user?.role !== "admin") {
        return res.status(403).send({ message: "Forbidden. Admin only." });
      }
      req.dbUser = user;
      next();
    };

    const verifyAdminOrVolunteer = async (req, res, next) => {
      const email = req.decodedUser?.email;
      if (!email) return res.status(401).send({ message: "Unauthorized." });

      const user = await Users.findOne({ email });
      if (!user || !["admin", "volunteer"].includes(user.role)) {
        return res
          .status(403)
          .send({ message: "Forbidden. Admin or volunteer only." });
      }
      req.dbUser = user;
      next();
    };

    // ===== Root health check =====
    app.get("/", (req, res) => {
      res.send("Blood Donation API is running.");
    });






    // ===========================
    //           USERS
    // ===========================

    // Create user document after Firebase sign-up / registration
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;

        if (!user || !user.email || !user.name) {
          return res.status(400).send({
            success: false,
            message: "Name and email are required.",
          });
        }

        const existing = await Users.findOne({ email: user.email });
        if (existing) {
          return res.status(409).send({
            success: false,
            message: "User with this email already exists.",
          });
        }

        const doc = {
          name: user.name,
          email: user.email,
          avatar: user.avatar || "",
          bloodGroup: user.bloodGroup || "",
          district: user.district || "",
          upazila: user.upazila || "",
          role: "donor", // default role
          status: "active", // default status
          createdAt: new Date(),
        };

        const result = await Users.insertOne(doc);

        return res.send({
          success: true,
          message: "User created successfully.",
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error("POST /users error:", error);
        return res.status(500).send({
          success: false,
          message: "Internal server error.",
        });
      }
    });



    // Get profile by email (owner or admin)
    app.get("/users/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const decodedEmail = req.decodedUser?.email;

        if (decodedEmail !== email) {
          const adminUser = await Users.findOne({ email: decodedEmail });
          if (adminUser?.role !== "admin") {
            return res
              .status(403)
              .send({ message: "Forbidden. Not allowed to read this user." });
          }
        }

        const user = await Users.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found." });
        }
        res.send(user);
      } catch (error) {
        console.error("GET /users/:email error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Update profile (owner or admin)
    app.put("/users/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const emailFromToken = req.decodedUser?.email;
        const payload = req.body;

        const userDoc = await Users.findOne({ _id: new ObjectId(id) });
        if (!userDoc) {
          return res.status(404).send({ message: "User not found." });
        }

        // Owner or admin only
        if (userDoc.email !== emailFromToken) {
          const adminUser = await Users.findOne({ email: emailFromToken });
          if (adminUser?.role !== "admin") {
            return res
              .status(403)
              .send({ message: "Forbidden. Cannot update this profile." });
          }
        }

        const updateDoc = {
          $set: {
            name: payload.name || userDoc.name,
            avatar: payload.avatar ?? userDoc.avatar,
            bloodGroup: payload.bloodGroup ?? userDoc.bloodGroup,
            district: payload.district ?? userDoc.district,
            upazila: payload.upazila ?? userDoc.upazila,
          },
        };

        const result = await Users.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );
        res.send({ success: true, result });
      } catch (error) {
        console.error("PUT /users/:id error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Admin: list all users with optional status filter & pagination
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const status = req.query.status; // active | blocked (optional)
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;

        const query = {};
        if (status === "active" || status === "blocked") {
          query.status = status;
        }

        const skip = (page - 1) * limit;

        const [items, total] = await Promise.all([
          Users.find(query).skip(skip).limit(limit).toArray(),
          Users.countDocuments(query),
        ]);

        const totalPages = Math.ceil(total / limit) || 1;

        res.send({
          items,
          total,
          totalPages,
          currentPage: page,
        });
      } catch (error) {
        console.error("GET /users error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });





    // Admin: block / unblock user
    app.patch("/users/:id/status", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body; // active | blocked

        if (!["active", "blocked"].includes(status)) {
          return res.status(400).send({ message: "Invalid status value." });
        }

        const result = await Users.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        res.send({ success: true, result });
      } catch (error) {
        console.error("PATCH /users/:id/status error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });





    // Admin: change role (donor / volunteer / admin)
    app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { role } = req.body; // donor | volunteer | admin

        if (!["donor", "volunteer", "admin"].includes(role)) {
          return res.status(400).send({ message: "Invalid role value." });
        }

        const result = await Users.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );

        res.send({ success: true, result });
      } catch (error) {
        console.error("PATCH /users/:id/role error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // ===========================
    //      DONATION REQUESTS
    // ===========================

    // Create donation request (only active users)
    app.post("/donation-requests", verifyToken, async (req, res) => {
      try {
        const email = req.decodedUser?.email;
        const user = await Users.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found." });
        }
        if (user.status === "blocked") {
          return res.status(403).send({
            message:
              "Your account is blocked. You cannot create donation requests.",
          });
        }

        const payload = req.body;

        const doc = {
          requesterName: payload.requesterName,
          requesterEmail: payload.requesterEmail,
          recipientName: payload.recipientName,
          recipientDistrict: payload.recipientDistrict,
          recipientUpazila: payload.recipientUpazila,
          hospitalName: payload.hospitalName,
          fullAddress: payload.fullAddress,
          bloodGroup: payload.bloodGroup,
          donationDate: payload.donationDate,
          donationTime: payload.donationTime,
          requestMessage: payload.requestMessage,
          status: "pending", // force default
          donor: null, // filled when someone confirms donation
          createdAt: new Date(),
        };

        const result = await DonationRequests.insertOne(doc);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (error) {
        console.error("POST /donation-requests error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Get current user's donation requests (with filters + pagination)
    app.get("/donation-requests/me", verifyToken, async (req, res) => {
      try {
        const email = req.decodedUser?.email;
        const status = req.query.status; // pending | inprogress | done | canceled
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;

        const query = { requesterEmail: email };
        if (["pending", "inprogress", "done", "canceled"].includes(status)) {
          query.status = status;
        }

        const skip = (page - 1) * limit;

        const [items, total] = await Promise.all([
          DonationRequests.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          DonationRequests.countDocuments(query),
        ]);

        const totalPages = Math.ceil(total / limit) || 1;

        res.send({
          items,
          total,
          totalPages,
          currentPage: page,
        });
      } catch (error) {
        console.error("GET /donation-requests/me error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Admin/Volunteer: get all donation requests (filters + pagination)
    app.get(
      "/donation-requests",
      verifyToken,
      verifyAdminOrVolunteer,
      async (req, res) => {
        try {
          const status = req.query.status;
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;

          const query = {};
          if (["pending", "inprogress", "done", "canceled"].includes(status)) {
            query.status = status;
          }

          const skip = (page - 1) * limit;

          const [items, total] = await Promise.all([
            DonationRequests.find(query)
              .sort({ createdAt: -1 })
              .skip(skip)
              .limit(limit)
              .toArray(),
            DonationRequests.countDocuments(query),
          ]);

          const totalPages = Math.ceil(total / limit) || 1;

          res.send({
            items,
            total,
            totalPages,
            currentPage: page,
          });
        } catch (error) {
          console.error("GET /donation-requests error:", error);
          res.status(500).send({ message: "Internal server error." });
        }
      }
    );




    // Get single donation request by id (any logged-in user)
    app.get("/donation-requests/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const doc = await DonationRequests.findOne({
          _id: new ObjectId(id),
        });
        if (!doc) {
          return res
            .status(404)
            .send({ message: "Donation request not found." });
        }
        res.send(doc);
      } catch (error) {
        console.error("GET /donation-requests/:id error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // Update donation request (owner or admin)
    app.put("/donation-requests/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decodedUser?.email;
        const payload = req.body;

        const reqDoc = await DonationRequests.findOne({
          _id: new ObjectId(id),
        });
        if (!reqDoc) {
          return res.status(404).send({ message: "Request not found." });
        }

        const currentUser = await Users.findOne({ email });
        const isOwner = reqDoc.requesterEmail === email;
        const isAdmin = currentUser?.role === "admin";

        if (!isOwner && !isAdmin) {
          return res
            .status(403)
            .send({ message: "Forbidden. Cannot edit this request." });
        }

        const updateDoc = {
          $set: {
            recipientName: payload.recipientName ?? reqDoc.recipientName,
            recipientDistrict:
              payload.recipientDistrict ?? reqDoc.recipientDistrict,
            recipientUpazila:
              payload.recipientUpazila ?? reqDoc.recipientUpazila,
            hospitalName: payload.hospitalName ?? reqDoc.hospitalName,
            fullAddress: payload.fullAddress ?? reqDoc.fullAddress,
            bloodGroup: payload.bloodGroup ?? reqDoc.bloodGroup,
            donationDate: payload.donationDate ?? reqDoc.donationDate,
            donationTime: payload.donationTime ?? reqDoc.donationTime,
            requestMessage: payload.requestMessage ?? reqDoc.requestMessage,
          },
        };

        const result = await DonationRequests.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        res.send({ success: true, result });
      } catch (error) {
        console.error("PUT /donation-requests/:id error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });




    // Delete request (owner or admin)
    app.delete("/donation-requests/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decodedUser?.email;

        const reqDoc = await DonationRequests.findOne({
          _id: new ObjectId(id),
        });

        if (!reqDoc) {
          return res.status(404).send({ message: "Request not found." });
        }

        const currentUser = await Users.findOne({ email });
        const isOwner = reqDoc.requesterEmail === email;
        const isAdmin = currentUser?.role === "admin";

        if (!isOwner && !isAdmin) {
          return res
            .status(403)
            .send({ message: "Forbidden. Cannot delete this request." });
        }

        const result = await DonationRequests.deleteOne({
          _id: new ObjectId(id),
        });

        res.send({ success: true, result });
      } catch (error) {
        console.error("DELETE /donation-requests/:id error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });




    // Update donation status – donor (claim), admin, volunteer
    app.patch("/donation-requests/:id/status", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const { status, donor } = req.body; // status required, donor optional
        const email = req.decodedUser?.email;

        if (!["pending", "inprogress", "done", "canceled"].includes(status)) {
          return res.status(400).send({ message: "Invalid status value." });
        }

        const reqDoc = await DonationRequests.findOne({
          _id: new ObjectId(id),
        });
        if (!reqDoc) {
          return res.status(404).send({ message: "Request not found." });
        }

        const currentUser = await Users.findOne({ email });

        const isOwner = reqDoc.requesterEmail === email;
        const isAdmin = currentUser?.role === "admin";
        const isVolunteer = currentUser?.role === "volunteer";

        // special case: donor confirming donation (pending -> inprogress)
        const isDonorConfirming =
          status === "inprogress" &&
          reqDoc.status === "pending" &&
          donor &&
          donor.email === email;

        if (!isOwner && !isAdmin && !isVolunteer && !isDonorConfirming) {
          return res
            .status(403)
            .send({ message: "Forbidden. Cannot change status." });
        }

        const updateDoc = {
          $set: {
            status,
          },
        };

        // when a donor claims a request, also store donor info
        if (donor) {
          updateDoc.$set.donor = donor; // { name, email }
        }

        const result = await DonationRequests.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        res.send({ success: true, result });
      } catch (error) {
        console.error("PATCH /donation-requests/:id/status error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });






    // ===========================
    //           STATS
    // ===========================

    app.get(
      "/stats/summary",
      verifyToken,
      verifyAdminOrVolunteer,
      async (req, res) => {
        try {
          const totalUsers = await Users.countDocuments({ role: "donor" });
          const totalRequests = await DonationRequests.countDocuments();

          let totalFunding = 0;
          const fundingAgg = await Funds.aggregate([
            {
              $group: {
                _id: null,
                sum: { $sum: "$amount" }, // expects funds with "amount"
              },
            },
          ]).toArray();
          if (fundingAgg.length) {
            totalFunding = fundingAgg[0].sum;
          }

          res.send({
            totalUsers,
            totalRequests,
            totalFunding,
          });
        } catch (error) {
          console.error("GET /stats/summary error:", error);
          res.status(500).send({ message: "Internal server error." });
        }
      }
    );

    // ===========================
    //       PUBLIC DONOR SEARCH
    // ===========================

    // PUBLIC: Search donors by blood group + district + upazila
    app.get("/donors/search", async (req, res) => {
      try {
        const { bloodGroup, district, upazila } = req.query;

        console.log("Search query:", req.query);

        if (!bloodGroup || !district || !upazila) {
          return res.status(400).send({
            message: "bloodGroup, district and upazila are required.",
          });
        }

        const query = {
          role: "donor",
          status: "active",
          bloodGroup,
          district,
          upazila,
        };

        const donorsCursor = Users.find(query, {
          projection: {
            password: 0,
          },
        });

        const donors = await donorsCursor.toArray();

        res.send(donors);
      } catch (error) {
        console.error("GET /donors/search error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });




    
    // ===========================
    //           ISSUES
    // ===========================

    app.get("/issues", async (req, res) => {
      try {
        const issues = await Issues.find().toArray();
        res.send(issues);
      } catch (error) {
        console.error("GET /issues error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    app.post("/issues", async (req, res) => {
      try {
        const issue = req.body;
        const result = await Issues.insertOne(issue);
        res.send(result);
      } catch (error) {
        console.error("POST /issues error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

    // ===========================
    //  PUBLIC: Pending Requests
    // ===========================

    // This is the public "Blood Donation requests" page
    // It returns ONLY pending requests with minimal fields.
    app.get("/public/donation-requests", async (req, res) => {
      try {
        const cursor = DonationRequests.find(
          { status: "pending" },
          {
            projection: {
              requesterName: 0,
              requesterEmail: 0,
              requestMessage: 0,
              donor: 0,
            },
          }
        ).sort({ createdAt: -1 });

        const items = await cursor.toArray();

        // Optionally map to ensure only required fields are sent
        const data = items.map((d) => ({
          _id: d._id,
          recipientName: d.recipientName,
          recipientDistrict: d.recipientDistrict,
          recipientUpazila: d.recipientUpazila,
          bloodGroup: d.bloodGroup,
          donationDate: d.donationDate,
          donationTime: d.donationTime,
        }));

        res.send(data);
      } catch (error) {
        console.error("GET /public/donation-requests error:", error);
        res.status(500).send({ message: "Internal server error." });
      }
    });

        // ===========================
    //           FUNDING
    // ===========================

    // Create Stripe PaymentIntent
    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      try {
        const { amount } = req.body;
        const email = req.decodedUser?.email;

        if (!amount || Number(amount) <= 0) {
          return res
            .status(400)
            .send({ message: "Valid amount is required for funding." });
        }

        const amountNumber = Number(amount);
        const amountInCents = Math.round(amountNumber * 100); // Stripe needs smallest currency unit

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amountInCents,
          currency: "usd", // use 'usd' for test mode; change only if you know what you’re doing
          metadata: {
            email: email || "",
          },
          automatic_payment_methods: {
            enabled: true,
          },
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error("POST /create-payment-intent error:", error);
        res.status(500).send({ message: "Failed to create payment intent." });
      }
    });

    // Save a fund record after successful payment
    app.post("/funds", verifyToken, async (req, res) => {
      try {
        const email = req.decodedUser?.email;
        const { amount, paymentIntentId } = req.body;

        if (!amount || Number(amount) <= 0 || !paymentIntentId) {
          return res.status(400).send({
            message: "amount and paymentIntentId are required.",
          });
        }

        const user = await Users.findOne({ email });
        const userName = user?.name || "";

        const fundDoc = {
          userEmail: email,
          userName,
          amount: Number(amount),
          paymentIntentId,
          createdAt: new Date(),
        };

        const result = await Funds.insertOne(fundDoc);
        res.send({
          success: true,
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error("POST /funds error:", error);
        res.status(500).send({ message: "Failed to save funding record." });
      }
    });

    // Get all funds (private, but any logged-in user can see)
    app.get("/funds", verifyToken, async (req, res) => {
      try {
        const funds = await Funds.find()
          .sort({ createdAt: -1 })
          .toArray();
        res.send(funds);
      } catch (error) {
        console.error("GET /funds error:", error);
        res.status(500).send({ message: "Failed to load funding data." });
      }
    });
        // ===========================
    //       CONTACT MESSAGES
    // ===========================

    // Public endpoint: anyone can send a message (no JWT)
    app.post("/messages", async (req, res) => {
      try {
        const { name, email, subject, message } = req.body || {};

        if (!name || !email || !subject || !message) {
          return res.status(400).send({
            message: "name, email, subject, and message are required.",
          });
        }

        const doc = {
          name,
          email,
          subject,
          message,
          createdAt: new Date(),
        };

        const result = await MessagesCollection.insertOne(doc);

        return res.send({
          success: true,
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error("POST /messages error:", error);
        return res
          .status(500)
          .send({ message: "Failed to save message. Try again later." });
      }
    });

    // (Optional) Protected endpoint: view all messages (admin only)
    // If you want, you can enable this later:
    
    app.get("/messages", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const messages = await MessagesCollection.find()
          .sort({ createdAt: -1 })
          .toArray();
        res.send(messages);
      } catch (error) {
        console.error("GET /messages error:", error);
        res.status(500).send({ message: "Failed to load messages." });
      }
    });
    




    console.log("All routes are ready.");
  } catch (err) {
    console.error("run() error:", err);
  }
}

run().catch(console.error);

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
