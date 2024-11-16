const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const port = process.env.PORT || 5000;
require('dotenv').config();


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token has expired' });
      }
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });

};

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

app.use(express.json());
app.use(cors());
const upload = multer({ dest: 'uploads/' });
const storage = multer.memoryStorage();

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@men-job-portal.ddye6po.mongodb.net/?retryWrites=true&w=majority`;

const uri = process.env.DATABASE_URL;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const transporter = nodemailer.createTransport({
  host: 'smtp.hostinger.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("MenJobPortal");
    const jobsCollections = db.collection("demoJobs");
    const usersCollection = db.collection("users");
    const jobApplicationsCollection = db.collection("jobApplications");
    const SUPER_ADMIN_EMAIL = "usama.mang0901@gmail.com";

    app.post("/post-job", async (req, res) => {
      try {
        let body = req.body;

        if (body.data) {
          body = body.data;
        }

        if (!body.companyName || !body.jobTitle || !body.useremail) {
          return res.status(400).send({
            message: "Company Name, Job Title, and User Email are required.",
            status: false
          });
        }

        body.createdAt = new Date();
        body.superAdminEmail = SUPER_ADMIN_EMAIL;

        let companyId = body.companyName
          .toLowerCase()
          .replace(/\s+/g, '-')
          .replace(/[^\w-]+/g, '');

        body.companyId = companyId;

        const result = await jobsCollections.insertOne(body);

        if (result.insertedId) {
          return res.status(201).send({
            message: "Job created successfully!",
            jobId: result.insertedId,
            status: true
          });
        } else {
          return res.status(500).send({
            message: "Failed to create job, try again later!",
            status: false
          });
        }
      } catch (error) {
        console.error(error);
        return res.status(500).send({
          message: "Internal Server Error",
          status: false
        });
      }
    });

    app.post("/update-job", async (req, res) => {
      try {
        let body = req.body;

        if (body.data) {
          body = body.data;
        }

        if (!body._id) {
          return res.status(400).send({
            message: "Job ID is required for updating.",
            status: false
          });
        }

        body._id = new ObjectId(body._id);
        body.updatedAt = new Date();
        body.superAdminEmail = body.superAdminEmail || "usama.mang0901@gmail.com";
        const result = await jobsCollections.findOneAndUpdate(
          { _id: body._id },
          { $set: body },
          { returnOriginal: false, upsert: false }
        );

        if (result) {
          return res.status(200).send({
            message: "Job updated successfully!",
            job: result,
            status: true
          });
        } else {
          return res.status(404).send({
            message: "Job not found!",
            status: false
          });
        }
      } catch (error) {
        console.error(error);
        return res.status(500).send({
          message: "Internal Server Error",
          status: false
        });
      }
    });

    app.get("/all-jobs", async (req, res) => {
      try {
        const jobs = await jobsCollections.find({}).toArray();
        res.send(jobs);
      } catch (error) {
        console.error(error);
        return res.status(500).send({
          message: "Internal Server Error",
          status: false
        });
      }
    });

    app.get("/company-jobs/:companyId", async (req, res) => {
      const companyId = req.params.companyId;

      try {
        const jobs = await jobsCollections.find({ companyId }).toArray();
        res.json(jobs);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    app.get("/location-jobs/:jobLocation", async (req, res) => {
      const jobLocation = req.params.jobLocation;

      try {
        const jobs = await jobsCollections.find({ jobLocation }).toArray();
        res.json(jobs);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    app.get("/categories/:category", async (req, res) => {
      const category = req.params.category;
      try {
        const jobs = await jobsCollections.find({ category }).toArray();
        res.json(jobs);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    app.get("/all-jobs/:id", async (req, res) => {
      const id = req.params.id;
      const job = await jobsCollections.findOne({
        _id: new ObjectId(id)
      });
      res.send(job);
    });

    app.get("/jobdetails/:id", async (req, res) => {
      const jobId = req.params.id;

      if (!ObjectId.isValid(jobId)) {
        return res.status(400).send({ message: 'Invalid job ID' });
      }

      try {
        const job = await jobsCollections.findOne({ _id: new ObjectId(jobId) });
        if (!job) {
          return res.status(404).send({ message: 'Job not found' });
        }
        res.json(job);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    app.get("/myJobs/:email", async (req, res) => {
      try {
        const userEmail = req.params.email;

        if (userEmail === SUPER_ADMIN_EMAIL) {
          const allJobs = await jobsCollections.find({}).toArray();
          return res.send(allJobs);
        } else {
          const userJobs = await jobsCollections.find({ useremail: userEmail }).toArray();
          return res.send(userJobs);
        }
      } catch (error) {
        console.error(error);
        return res.status(500).send({
          message: "Internal Server Error",
          status: false
        });
      }
    });

    app.delete("/job/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const result = await jobsCollections.deleteOne(filter);
      res.send(result);
    });

    app.post("/signup", async (req, res) => {
      const { firstName, lastName, email, password, phoneNumber } = req.body;

      try {
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = new ObjectId();

        const newUser = {
          _id: userId,
          firstName,
          lastName,
          email,
          password: hashedPassword,
          phoneNumber,
        };

        await usersCollection.insertOne(newUser);

        res.status(201).json({ message: "User created successfully", userId });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
    
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
    
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res.status(401).json({ message: "Invalid credentials" });
        }
    
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
        const likedJobs = user.likedJobs;  
    
        res.json({ token, name: user.firstName, userId: user._id, likedJobs });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
    

    app.get('/user-info/:email', async (req, res) => {
      const userEmail = req.params.email;
      try {
        const user = await usersCollection.findOne({ email: userEmail });

        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
      } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });

    app.post("/job/like", authenticateToken, async (req, res) => {
      const { jobId, userId, action } = req.body;
    
      if (!jobId || !userId || !action) {
        return res.status(400).json({ message: "Invalid request. Job ID, user ID, and like/unlike action are required." });
      }
    
      try {
        const job = await jobsCollections.findOne({ _id: new ObjectId(jobId) });
    
        if (!job) {
          return res.status(404).json({ message: "Job not found." });
        }
    
        if (action === "like") {
          // Add job to the user's liked jobs
          await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $addToSet: { likedJobs: jobId } } // Prevent duplicates with $addToSet
          );
        } else if (action === "unlike") {
          // Remove job from the user's liked jobs
          await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $pull: { likedJobs: jobId } } // Remove the job ID from the list
          );
        } else {
          return res.status(400).json({ message: "Invalid action. Use 'like' or 'unlike'." });
        }
    
        res.status(200).json({ success: true, message: `Job successfully ${action}d.` });
      } catch (error) {
        console.error("Error updating liked jobs:", error);
        res.status(500).json({ message: "Internal server error." });
      }
    });
    

    app.post('/apply', authenticateToken, upload.single('cvFile'), async (req, res) => {
      const { coverLetter, companyemail, companyjob, companyname, name, jobId, email } = req.body;
      const cvFile = req.file;

      if (!coverLetter || !cvFile || !name || !email) {
        return res.status(400).send('All fields are required.');
      }

      try {
        const userId = req.user.userId;

        const existingApplication = await jobApplicationsCollection.findOne({ userId, jobId });
        if (existingApplication) {
          return res.status(400).json({ message: 'You have already applied for this job.' });
        }
        const upload = multer({ dest: 'uploads/' });
        await jobApplicationsCollection.insertOne({
          userId,
          jobId,
          coverLetter,
          cvFilePath: cvFile.path,
          appliedAt: new Date(),
        });

        const mailOptionsToUser = {
          from: 'jobs@aidifys.com',
          to: email,
          subject: 'Job Application Received',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #dddddd; border-radius: 8px; background-color: #f9f9f9;">
                <h2 style="text-align: center; color: #333333;">Job Application Received</h2>
                <p style="font-size: 16px; color: #555555;">Dear Applicant,</p>
                <p style="font-size: 16px; color: #555555;">
                    Thank you for applying for the position of <strong>${companyjob}</strong> at <strong>${companyname}</strong>. We have received your application.
                </p>
                <p style="font-size: 16px; color: #555555; text-align: center;">
                You can visit our website for more job opportunities: <a href="https://aidifys.com/" style="color: #1a73e8;">Aidifys</a>
                </p>
                <p style="font-size: 16px; color: #555555;">
                    Best regards,<br/>
                    <strong>${companyname}</strong>
                </p>
            </div>
          `
        };

        const mailOptionsToCompany = {
          from: 'jobs@aidifys.com',
          to: companyemail,
          subject: 'New Job Application',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #dddddd; border-radius: 8px; background-color: #f9f9f9;">
                <h2 style="text-align: center; color: #333333;">New Job Application Received</h2>
                <p style="font-size: 16px; color: #555555;">A new job application has been received from <strong>${email}</strong>.</p>
                <p style="font-size: 16px; color: #555555;">
                    <strong>Job Title:</strong> ${companyjob}<br/>
                    <strong>Applicant Name:</strong> ${name}
                </p>
                <p style="font-size: 16px; color: #555555;"><strong>Cover Letter:</strong></p>
                <div style="font-size: 16px; color: #555555; border-left: 4px solid #dddddd; padding-left: 16px; margin: 16px 0;">
                    ${coverLetter}
                </div>
            </div>
          `,
          attachments: [
            {
              filename: cvFile.originalname,
              path: cvFile.path
            }
          ]
        };

        transporter.sendMail(mailOptionsToUser, (error, info) => {
          if (error) {
            console.error('Error sending email to user:', error);
          } else {
          }
        });

        transporter.sendMail(mailOptionsToCompany, (error, info) => {
          if (error) {
            console.error('Error sending email to company:', error);
            return res.status(500).send('Error submitting application.');
          } else {
            res.status(200).json({
              success: true,
              message: "Application Submitted Successfully!",
              data: mailOptionsToCompany
            });
          }
        });
      } catch (error) {
        console.error('Error applying for job:', error);
        res.status(500).send('Internal Server Error');
      }
    });
    app.get('/user-applied-jobs', authenticateToken, async (req, res) => {
      try {
        const userId = req.user.userId;

        const applications = await jobApplicationsCollection.find({ userId }).toArray();
        const jobIds = applications.map(app => app.jobId);

        const jobs = await jobsCollections.find({ _id: { $in: jobIds.map(id => new ObjectId(id)) } }).toArray();

        res.json(jobs);
      } catch (error) {
        console.error('Error fetching user applied jobs:', error);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });

    app.post('/generate-signature', (req, res) => {
      const timestamp = Math.round((new Date()).getTime() / 1000);
      const signature = cloudinary.utils.api_sign_request({
        timestamp: timestamp,
        upload_preset: 'Aidifys'
      }, process.env.CLOUDINARY_API_SECRET);

      res.json({ timestamp, signature });
    });

    await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Haris!');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
