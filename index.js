const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
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
const imageUpload = multer({ storage: storage });
const logoUrl = "https://res.cloudinary.com/dfs0l1ady/image/upload/v1734176190/weblogo_wvjxtg.jpg";

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
  // logger: true,
  // debug: true
});

// const transporter = nodemailer.createTransport({
//   service: 'Gmail',
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   }
// });

async function run() {
  try {
    await client.connect();
    const db = client.db("MenJobPortal");
    const jobsCollections = db.collection("demoJobs");
    const usersCollection = db.collection("users");
    const jobApplicationsCollection = db.collection("jobApplications");
    const otpCollection = db.collection("otp");
    const blogsCollection = db.collection("blogs");
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

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        await otpCollection.insertOne({
          email,
          otp,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        });

        try {
          await transporter.sendMail({
            from: "jobs@aidifys.com",
            to: email,
            subject: "Signup OTP Verification Code",
            html: `
           <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #F7F9FC; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto;">
                <!-- Logo -->
                <div style="margin-bottom: 20px;">
                  <img src="${logoUrl}" alt="Company Logo" style="max-width: 150px; height: auto;" />
                </div>
    
                <!-- OTP Message -->
                <h2 style="color: #007BFF;">Your OTP code for Signup</h2>
                <p style="font-size: 18px; font-weight: bold; margin: 20px 0;">
                  ${otp}
                </p>
                <p style="font-size: 14px; color: #555;">
                  This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.
                </p>
    
                <!-- Footer -->
                <p style="font-size: 12px; color: #999; margin-top: 30px;">
                  &copy; ${new Date().getFullYear()} Aidifys Hiring. All Rights Reserved.
                </p>
              </div>
            `,
          });

          res.status(200).json({ message: "OTP sent to email. Please verify." });
        } catch (error) {
          console.error("Email send error:", error);
          return res.status(500).json({ message: "Failed to send OTP email." });
        }
      } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    app.post("/verify-otp", async (req, res) => {
      const { email, otp } = req.body;
    
      try {
        const record = await otpCollection.findOne({ email });
    
        if (!record) {
          return res.status(400).json({ message: "Invalid OTP or email." });
        }
    
        if (record.expiresAt < new Date()) {
          return res.status(400).json({ message: "OTP expired. Please request a new OTP." });
        }
    
        const inputOtp = otp.join("");
    
        if (record.otp !== inputOtp) {
          return res.status(400).json({ message: "Incorrect OTP." });
        }
    
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = {
          firstName: req.body.firstName,
          lastName: req.body.lastName,
          email,
          password: hashedPassword,
          phoneNumber: req.body.phoneNumber,
        };
    
        await usersCollection.insertOne(newUser);
        await otpCollection.deleteOne({ email });
    
        res.status(201).json({ message: "User created successfully" });
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
    

    app.post("/resend-otp", async (req, res) => {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required." });
      }

      try {
        const existingOtpRecord = await otpCollection.findOne({ email });
        if (!existingOtpRecord) {
          return res.status(400).json({ message: "No OTP request found for this email." });
        }

        const newOtp = Math.floor(100000 + Math.random() * 900000).toString();

        await otpCollection.updateOne(
          { email },
          {
            $set: {
              otp: newOtp,
              createdAt: new Date(),
              expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            },
          }
        );

        try {
          await transporter.sendMail({
            from: "jobs@aidifys.com",
            to: email,
            subject: "Resend OTP Verification Code",
            html: `
           <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #F7F9FC; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto;">
                <!-- Logo -->
                <div style="margin-bottom: 20px;">
                  <img src="${logoUrl}" alt="Company Logo" style="max-width: 150px; height: auto;" />
                </div>
    
                <!-- OTP Message -->
                <h2 style="color: #007BFF;">Your New OTP for Verification Code</h2>
                <p style="font-size: 18px; font-weight: bold; margin: 20px 0;">
                  ${newOtp}
                </p>
                <p style="font-size: 14px; color: #555;">
                  This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.
                </p>
    
                <!-- Footer -->
                <p style="font-size: 12px; color: #999; margin-top: 30px;">
                  &copy; ${new Date().getFullYear()} Aidifys Hiring. All Rights Reserved.
                </p>
              </div>
            `,
          });

          res.status(200).json({ message: "OTP resent to your email." });
        } catch (emailError) {
          console.error("Error sending email:", emailError);
          return res.status(500).json({ message: "Failed to resend OTP email." });
        }
      } catch (error) {
        console.error("Resend OTP error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    app.post("/forgot-password", async (req, res) => {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required." });
      }

      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found." });
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000);

        await usersCollection.updateOne(
          { email },
          { $set: { resetToken, resetTokenExpiry } }
        );

        const resetLink = `https://www.aidifys.com/reset-password?token=${resetToken}`;
        
        ////local link ///
        // const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

        await transporter.sendMail({
          from: "jobs@aidifys.com",
          to: email,
          subject: "Password Reset Request",
          html: `
           <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #F7F9FC; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto;">
          <!-- Logo -->
          <div style="text-align: center; margin-bottom: 20px;">
          <img src="${logoUrl}" alt="Company Logo" style="max-width: 150px; height: auto;" />
          </div>

           <!-- Title -->
          <h2 style="text-align: center; color: #333; margin-bottom: 20px;">Need a New Password?</h2>

           <!-- Text -->
         <p style="text-align: center; color: #555; font-size: 16px; margin-bottom: 30px;">
          No worries. Click the button below to reset and choose a new one. This link is valid for <strong>1 hour</strong>.
         </p>

          <!-- Button -->
          <div style="text-align: center; margin: 20px;">
          <a href="${resetLink}"
           style="display: inline-block; background-color: #3b82f6; color: #ffffff; padding: 12px 25px; font-size: 16px; text-decoration: none; border-radius: 5px; font-weight: bold;">
            Reset Password
           </a>
          </div>

         <!-- Footer -->
       <p style="text-align: center; color: #777; font-size: 14px; margin-top: 40px;">
        Didn’t request this change? You can ignore this email and get back to 
        <a href="https://aidifys.com/" style="color: #1a73e8; text-decoration: none;">Aidifys Hiring</a>.
        </p>
  
        <p style="text-align: center; font-size: 12px; color: #999; margin-top: 20px;">
            &copy; ${new Date().getFullYear()} Aidifys Hiring. All Rights Reserved.
          </p>
        </div>

          `,
        });

        res.status(200).json({ message: "Password reset link sent to your email." });
      } catch (error) {
        console.error("Error in forgot-password API:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    app.post("/reset-password", async (req, res) => {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({ message: "Token and new password are required." });
      }

      try {
        const user = await usersCollection.findOne({
          resetToken: token,
          resetTokenExpiry: { $gt: new Date() },
        });

        if (!user) {
          return res.status(400).json({ message: "Invalid or expired token." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await usersCollection.updateOne(
          { email: user.email },
          {
            $set: { password: hashedPassword },
            $unset: { resetToken: "", resetTokenExpiry: "" },
          }
        );

        res.status(200).json({ message: "Password has been reset successfully." });
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
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
          await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $addToSet: { likedJobs: jobId } }
          );
        } else if (action === "unlike") {
          await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $pull: { likedJobs: jobId } }
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
           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #dddddd; border-radius: 8px; background-color: #f9f9f9; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
    <div style="text-align: center; margin-bottom: 30px;">
        <img src="${logoUrl}" alt="Company Logo" style="max-width: 150px; height: auto; margin: 0 auto; display: block;" />
    </div>
    <h2 style="text-align: center; color: #333333; font-size: 24px; font-weight: 600; margin-bottom: 20px;">
        Job Application Received
    </h2>
    <p style="font-size: 16px; color: #555555; line-height: 1.6;">
        Dear Applicant,
    </p>
    <p style="font-size: 16px; color: #555555; line-height: 1.6;">
        Thank you for applying for the position of <strong>${companyjob}</strong> at <strong>${companyname}</strong>. We have received your application.
    </p>
    <p style="font-size: 16px; color: #555555; text-align: center; line-height: 1.6;">
        You can visit our website for more job opportunities: 
        <a href="https://aidifys.com/" style="color: #1a73e8; text-decoration: none; font-weight: 600;">
            Aidifys Hiring
        </a>
    </p>
    <p style="font-size: 16px; color: #555555; line-height: 1.6;">
        Best regards,<br/>
        <strong>Aidifys Hiring</strong>
    </p>
</div>

          `
        };

        const mailOptionsToCompany = {
          from: "jobs@aidifys.com",
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
    app.post("/create-blog", imageUpload.single("image"), async (req, res) => {
      const { title, content } = req.body;
      const image = req.file;

      if (!title || !content || !image) {
        return res.status(400).json({ message: "All fields are required, including the image" });
      }

      try {
        const uploadResponse = await cloudinary.uploader.upload_stream(
          { folder: "blogs", resource_type: "auto" },
          async (error, result) => {
            if (error) {
              console.error("Cloudinary upload error:", error);
              return res.status(500).json({ message: "Error uploading to Cloudinary", error: error.message });
            }

            const newBlog = {
              title,
              content,
              imageUrl: result.secure_url,
              cloudinaryId: result.public_id,
              createdAt: new Date(),
            };

            const result1 = await blogsCollection.insertOne(newBlog);
            res.status(201).json({ message: "Blog created successfully", blogId: result1.insertedId });
          }
        );

        uploadResponse.end(image.buffer);

      } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ message: "Internal Server Error", error: error.message });
      }
    });

    app.delete("/delete-blog/:id", async (req, res) => {
      const { id } = req.params;

      try {
        const blog = await blogsCollection.findOne({ _id: new ObjectId(id) });

        if (!blog) {
          return res.status(404).json({ message: "Blog not found." });
        }

        if (blog.cloudinaryId) {
          await cloudinary.uploader.destroy(blog.cloudinaryId);
        }

        const result = await blogsCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Blog not found." });
        }

        res.status(200).json({ message: "Blog and its image deleted successfully" });
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message });
      }
    });
    app.get("/blog-detail/:id", async (req, res) => {
      const { id } = req.params;

      try {
        const blog = await blogsCollection.findOne({ _id: new ObjectId(id) });

        if (!blog) {
          return res.status(404).json({ message: "Blog not found." });
        }

        res.status(200).json({ blog });
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
    app.get("/blogs", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 9;

      const skip = (page - 1) * limit;

      try {
        const totalBlogs = await blogsCollection.countDocuments();
        const blogs = await blogsCollection.find().skip(skip).limit(limit).toArray();

        res.status(200).json({
          blogs,
          totalBlogs,
          totalPages: Math.ceil(totalBlogs / limit),
          currentPage: page,
        });
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message });
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
