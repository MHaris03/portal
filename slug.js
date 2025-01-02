require('dotenv').config(); // Load environment variables from .env file

const { MongoClient, ObjectId } = require("mongodb");

const uri = process.env.DATABASE_URL; // MongoDB connection string
if (!uri) {
  console.error("DATABASE_URL is not defined in the .env file");
  process.exit(1); // Exit if DATABASE_URL is not defined
}

const client = new MongoClient(uri);

const SUPER_ADMIN_EMAIL = "usama.mang0901@gmail.com"; // Replace with your actual email

// Function to generate a slug without using slugify
async function generateUniqueSlug(jobTitle, existingId = null, jobsCollections) {
    let baseSlug = jobTitle
        .trim()
        .toLowerCase()
        .replace(/\s+/g, '-') // Replace spaces with hyphens
        .replace(/[^\w-]+/g, ''); // Remove special characters

    let uniqueSlug = baseSlug;
    let counter = 1;

    // Check for uniqueness in the database
    while (true) {
        const query = { slug: uniqueSlug };

        if (existingId) {
            query._id = { $ne: new ObjectId(existingId) };
        }

        const existingJob = await jobsCollections.findOne(query);

        if (!existingJob) {
            break;
        }

        uniqueSlug = `${baseSlug}-${counter}`;
        counter++;
    }

    return uniqueSlug;
}

// Script to add slugs to existing jobs
async function addSlugsToExistingJobs() {
    try {
        await client.connect();
        const db = client.db("MenJobPortal");
        const jobsCollections = db.collection("demoJobs");

        const jobs = await jobsCollections.find({ slug: { $exists: false } }).toArray();

        for (const job of jobs) {
            const slug = await generateUniqueSlug(job.jobTitle, job._id, jobsCollections);

            const updateResult = await jobsCollections.updateOne(
                { _id: new ObjectId(job._id) },
                {
                    $set: {
                        slug,
                        superAdminEmail: SUPER_ADMIN_EMAIL,
                    },
                }
            );

            if (updateResult.modifiedCount > 0) {
                console.log(`Slug added for Job ID ${job._id}: ${slug}`);
            } else {
                console.warn(`Failed to update Job ID ${job._id}`);
            }
        }

        console.log("Slugs added to all applicable jobs.");
    } catch (error) {
        console.error("Error adding slugs:", error);
    } finally {
        await client.close();
    }
}

addSlugsToExistingJobs();
