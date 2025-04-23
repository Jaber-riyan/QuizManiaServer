require("dotenv").config();

const { GoogleGenerativeAI } = require("@google/generative-ai");
const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(
    cors({
        origin: [
            "http://localhost:3000",
            "https://quizmaniaa.vercel.app",
            "https://quiz-maniaa.vercel.app",
            "https://quizzmaniaa.vercel.app",
        ],
        credentials: true,
    })
);
app.use(cookieParser());

// MongoDB connection
const uri = `mongodb+srv://${process.env.USER_NAME}:${process.env.PASSWORD}@cluster0.4ayta.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Gemini API client
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    try {
        console.log("✅ Successfully connected to MongoDB!");

        // Database
        const database = client.db("QuizMania");

        // Quizzes Collection
        const quizzesCollection = database.collection("quizzes");

        // Users Collection
        const usersCollection = database.collection("users");

        // Reset Password Expire Collection
        const expireCollection = database.collection("expire");

        // Quiz Set Collection For Teacher 
        const quizSet = database.collection("quizset")

        // verify token middleware
        const verifyToken = (req, res, next) => {
            // console.log("Inside the verify token");
            // console.log("received request:", req?.headers?.authorization);
            if (!req?.headers?.authorization) {
                return res.status(401).json({ message: "Unauthorized Access!" });
            }

            // get token from the headers 
            const token = req?.headers?.authorization;
            // console.log("Received Token", token);

            jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
                if (err) {
                    console.error('JWT Verification Error:', err.message);
                    return res.status(401).json({ message: err.message });
                }
                // console.log('Decoded Token:', decoded);
                req.user = decoded;
                next();
            })
        }

        // verify admin middleware after verify token
        const verifyAdmin = async (req, res, next) => {
            const email = req.user.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            next();
        }

        // JWT token create and remove APIS
        // JWT token create API 
        app.post('/jwt/create', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '7h' });
            res.send({ token })
        })


        // Create quiz API
        app.post("/generate-quiz", async (req, res) => {
            try {
                const { user, quizCriteria } = req.body;

                // **Improved Prompting for Strict JSON Response**

                const prompt = `
                    Generate a ${quizCriteria.difficulty} level quiz on "${quizCriteria.topic}" with ${quizCriteria.quizType} questions.
                    - Number of Questions: ${quizCriteria.quantity}
                    - Return ONLY a valid JSON array. No extra text.
                    - Each question should have:
                        - "type": (Multiple Choice / True or False)
                        - "question": (Text of the question)
                        - "options": (An array of choices, required only for "Multiple Choice" and "True/False" question types. For "True/False" questions, the allowed options are only ["True", "False"] but for multiple choice there should be no true or false as  options)
                        - "answer": (Correct answer)
                    
                    Example Output:
                    [
                        {
                            "type": "Multiple Choice",
                            "question": "What is the capital of France?",
                            "options": ["Berlin", "Paris", "Madrid", "Rome"],
                            "answer": "Paris"
                        }
                    ]
                    Do not include explanations, code blocks, or markdown. Just return raw JSON data.
                `;

                // Call Gemini API to generate content
                const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

                const response = await model.generateContent([prompt]);

                const quizData = response.response.candidates[0].content.parts[0].text;
                // const demo = response.response

                // console.log("🔹 Raw AI Response:", quizData);

                // **Extract JSON if wrapped in extra text**
                const jsonMatch = quizData.match(/```json([\s\S]*?)```/);
                const cleanJson = jsonMatch ? jsonMatch[1].trim() : quizData;

                // Parse the quiz data
                let parsedQuizData;
                try {
                    parsedQuizData = JSON.parse(cleanJson);
                } catch (error) {
                    console.error("❌ JSON Parsing Error:", error);
                    throw new Error("Invalid JSON format received from AI.");
                }

                const updatedData = {
                    user,
                    quizCriteria,
                    parsedQuizData,
                };

                const result = await quizzesCollection.insertOne(updatedData);

                // Send the response
                res.json({
                    status: true,
                    message: "✅ Successfully generated quiz from AI",
                    result,
                    user,
                    quizCriteria,
                    quizzes: parsedQuizData,
                });
            } catch (err) {
                console.error("❌ Error generating quiz:", err);
                res.status(500).json({ status: false, message: err.message });
            }
        });

        // Create quiz API for Teacher API
        app.post('/teacher/generate-quiz', async (req, res) => {
            try {
                const { user, ...teacherCreatedQuiz } = req.body

                const userExist = await usersCollection.findOne({ email: user })
                // if(userExist?.role=="teacher")
                const result = await quizSet.insertOne(req.body)
                const insertedQuiz = await quizSet.findOne({ _id: new ObjectId(result?.insertedId) })
                res.json({
                    status: true,
                    result,
                    insertedQuiz
                })
            }
            catch (err) {
                console.error("❌ Error checking quiz:", err);
                res.status(500).json({ status: false, message: err.message });
            }
        })

        // get the quiz set that user just created API
        app.get("/get-quiz-set/:id", async (req, res) => {
            const id = req.params.id;
            const result = await quizzesCollection.findOne({ _id: new ObjectId(id) });
            res.json(result);
        });

        // Get the Teacher Created Quiz API 
        app.get('/teacher/generate-quiz/:id', async(req, res)=>{
            const id = req.params.id;
            const result = await quizSet.findOne({ _id: new ObjectId(id) });
            res.json(result);
        });

        // checking the quiz answer API
        app.post("/answer/checking", async (req, res) => {
            try {
                const { id, answers } = req.body;
                let quizSet = await quizzesCollection.findOne({
                    _id: new ObjectId(id),
                });

                if (!quizSet) {
                    return res.json({ status: false, message: "Quiz not found" });
                }

                const totalQuizInSet = quizSet.parsedQuizData.length;
                let correctQuizAnswer = 0; // ✅ Initialize properly

                const updatePromises = answers.map((answer, index) => {
                    const quizQuestion = quizSet.parsedQuizData[index];

                    if (
                        quizQuestion.question === answer.question &&
                        quizQuestion.answer === answer.userAnswer
                    ) {
                        correctQuizAnswer++; // ✅ Synchronously update count
                    }

                    return quizzesCollection.updateOne(
                        {
                            _id: new ObjectId(id),
                            "parsedQuizData.question": quizQuestion.question,
                        },
                        {
                            $set: {
                                "parsedQuizData.$.userAnswer": answer.userAnswer,
                                "parsedQuizData.$.status":
                                    answer.userAnswer === quizQuestion.answer
                                        ? "correct"
                                        : "wrong",
                            },
                        }
                    );
                });

                await Promise.all(updatePromises); // ✅ Wait for all updates

                // ✅ Update correct & incorrect answer counts in the database
                await quizzesCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            correctQuizAnswer,
                            wrongQuizAnswer: totalQuizInSet - correctQuizAnswer,
                            status: "solved",
                        },
                    }
                );

                // override quizSet
                quizSet = await quizzesCollection.findOne({ _id: new ObjectId(id) });

                res.json({
                    status: true,
                    totalQuizInSet,
                    quizSet,
                    correctQuizAnswer, // ✅ Now this should not be NaN
                    wrongQuizAnswer: totalQuizInSet - correctQuizAnswer, // ✅ Ensure correct value
                });
            } catch (err) {
                console.error("❌ Error checking quiz:", err);
                res.status(500).json({ status: false, message: err.message });
            }
        });

        // stored user into the mongodb API
        app.post("/signup", async (req, res) => {
            try {
                const { sociallogin } = req.query;
                if (sociallogin) {
                    const body = req.body;

                    const existingUser = await usersCollection.findOne({
                        email: body?.email,
                    });

                    if (existingUser) {
                        return res.json({
                            status: false,
                            message: "User already exists, use another email address",
                            data: result,
                        });
                    }

                    const updateBody = {
                        ...body,
                        role: "user",
                        failedAttempts: 0,
                        block: false,
                    };

                    const result = await usersCollection.insertOne(updateBody);
                    return res.json({
                        status: true,
                        message: "User added successfully",
                        result,
                    });
                } else {
                    const { password, ...user } = req.body;
                    const existingUser = await usersCollection.findOne({
                        email: user?.email,
                    });

                    if (existingUser) {
                        return res.json({
                            status: false,
                            message: "User already exists, use another email address",
                            data: result,
                        });
                    }

                    const hashedPass = await bcrypt.hash(password, 10);

                    const withRole = {
                        ...user,
                        password: hashedPass,
                        role: "user",
                        failedAttempts: 0,
                        block: false,
                    };
                    const insertResult = await usersCollection.insertOne(withRole);
                    return res.json({
                        status: true,
                        message: "User added successfully",
                        data: insertResult,
                    });
                }
            } catch (error) {
                console.error("Error adding/updating user:", error);
                res.status(500).json({
                    status: false,
                    message: "Failed to add or update userr",
                    error: error.message,
                });
            }
        });

        // get a user from the mongodb by email API
        app.post("/signin/:email", async (req, res) => {
            const email = req.params.email;

            const { password, ...userInfo } = req.body;

            let user = await usersCollection.findOne({ email });
            if (!user) {
                res.json({ status: false, message: "User not found" });
                return;
            }

            if (user?.block) {
                res.json({
                    status: false,
                    message: "This Email has been blocked, Please contact with admin!",
                });
                return;
            }

            const match = await bcrypt.compare(password, user?.password);

            if (!match) {
                if (user?.failedAttempts == 4) {
                    await usersCollection.updateOne(
                        { email: email },
                        {
                            $set: {
                                block: true,
                            },
                        }
                    );
                    res.json({
                        status: false,
                        message: "Your Email Has been blocked Please contact with admin!",
                    });
                    return;
                } else {
                    const updateFailedAttempts = {
                        $inc: {
                            failedAttempts: 1,
                        },
                    };
                    await usersCollection.updateOne(
                        { email: email },
                        updateFailedAttempts
                    );
                    user = await usersCollection.findOne({ email: email });
                    res.json({
                        status: false,
                        message: `Incorrect Password, Left ${5 - user?.failedAttempts
                            } Attempts`,
                        failedAttempts: user?.failedAttempts,
                    });
                    return;
                }
            }

            await usersCollection.updateOne(
                { email: email },
                {
                    $set: {
                        failedAttempts: 0,
                    },
                }
            );

            const updatedData = {
                $set: {
                    lastLoginTime: userInfo?.lastLoginTime,
                },
            };

            await usersCollection.updateOne({ email: user?.email }, updatedData);
            res.json({
                status: true,
                userInfo: user,
                message: "Login Successfully",
            });
        });

        // get user for auth js API
        app.get("/signin/:email", async (req, res) => {
            const email = req.params.email;
            const userExist = await usersCollection.findOne({ email: email });
            if (!userExist) {
                res.json({ status: false, message: "User Not Found" });
                return;
            }
            res.json({
                status: true,
                userInfo: userExist,
            });
        });

        // update user info API 
        app.patch('/user/update/profile/:id', async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ status: false, message: "Invalid user ID" });
                }

                const body = req.body;
                const updatedDoc = {
                    $set: {
                        username: body?.username,
                        phone: body?.phone,
                    }
                };

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    updatedDoc
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ status: false, message: "User not found" });
                }

                res.status(200).json({
                    status: true,
                    message: "User profile updated successfully",
                    result
                });
            } catch (error) {
                console.error("Error updating user profile:", error);
                res.status(500).json({
                    status: false,
                    message: "Something went wrong",
                    error: error.message
                });
            }
        });

        // delete user from db API 
        app.delete('/user/delete/:id', async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ status: false, message: "Invalid user ID" });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) })
                const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
                await quizzesCollection.deleteMany({ email: user?.email })


                if (result.deletedCount === 0) {
                    return res.status(404).json({ status: false, message: "User not found" });
                }

                res.status(200).json({
                    status: true,
                    message: "User deleted successfully",
                    result
                });
            } catch (error) {
                console.error("Error deleting user:", error);
                res.status(500).json({
                    status: false,
                    message: "Something went wrong",
                    error: error.message
                });
            }
        });

        // change role of user API 
        app.patch('/user/role/change/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const user = await usersCollection.findOne({ _id: new ObjectId(id) })

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({ status: false, message: "Invalid user ID" });
                }

                if (!role) {
                    return res.status(400).json({ status: false, message: "Role is required" });
                }

                const updatedDoc = {
                    $set: {
                        role: user?.role == "admin" ? "user" : "admin"
                    }
                };

                const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, updatedDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).json({ status: false, message: "User not found" });
                }

                res.status(200).json({
                    status: true,
                    message: "User role updated successfully",
                    result
                });
            } catch (error) {
                console.error("Error updating user role:", error);
                res.status(500).json({
                    status: false,
                    message: "Something went wrong",
                    error: error.message
                });
            }
        });

        // reset password API
        app.get("/reset-password/:email", async (req, res) => {
            const email = req.params.email;
            const userExist = await usersCollection.findOne({ email: email });
            if (!userExist) {
                res.json({ status: false, message: "User Not Found!" });
                return;
            }

            const expireUserExist = await expireCollection.findOne({ email: email });

            if (!expireUserExist) {
                await expireCollection.insertOne({
                    email: email,
                    expiresAt: new Date(Date.now() + 1000 * 60 * 5), // 5 min
                });
            }

            if (expireUserExist) {
                await expireCollection.updateOne(
                    { email: email },
                    {
                        $set: {
                            expiresAt: new Date(Date.now() + 1000 * 60 * 5), // 5 min
                        },
                    }
                );
            }

            const html = `
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Reset Your Password - QuizMania</title>
                <style>
                  @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');
            
                  body {
                    font-family: 'Poppins', sans-serif;
                    background-color: #f3f4f6;
                    margin: 0;
                    padding: 0;
                    color: #1f2937;
                  }
            
                  .email-container {
                    max-width: 600px;
                    margin: 40px auto;
                    background-color: #ffffff;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
                  }
            
                  .email-header {
                    background-color: #8b5cf6;
                    padding: 30px 20px;
                    text-align: center;
                  }
            
                  .logo {
                    font-size: 26px;
                    font-weight: 700;
                    color: #ffffff;
                    letter-spacing: 1px;
                  }
            
                  .email-body {
                    padding: 40px 30px;
                  }
            
                  .greeting {
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 20px;
                  }
            
                  .message {
                    font-size: 16px;
                    line-height: 1.6;
                    margin-bottom: 25px;
                  }
            
                  .reset-button {
                    display: inline-block;
                    background-color: #8b5cf6;
                    color: #ffffff !important;
                    text-decoration: none;
                    padding: 14px 36px;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 16px;
                    transition: background-color 0.3s ease;
                  }
            
                  .reset-button:hover {
                    background-color: #7c3aed;
                  }
            
                  .warning {
                    font-size: 14px;
                    color: #6b7280;
                    margin-top: 30px;
                    font-style: italic;
                  }
            
                  .email-footer {
                    background-color: #f9fafb;
                    padding: 20px;
                    text-align: center;
                    font-size: 14px;
                    color: #6b7280;
                  }
            
                  @media only screen and (max-width: 600px) {
                    .email-body {
                      padding: 30px 20px;
                    }
            
                    .reset-button {
                      width: 100%;
                      padding: 14px 0;
                    }
            
                    .logo {
                      font-size: 22px;
                    }
                  }
                </style>
              </head>
              <body>
                <div class="email-container">
                  <div class="email-header">
                    <div class="logo">QuizMania</div>
                  </div>
                  <div class="email-body">
                    <div class="greeting">Hi, ${userExist.username}</div>
                    <div class="message">
                      We received a request to reset the password associated with your QuizMania account.
                      Click the button below to continue with the reset process.
                    </div>
                    <a href="https://quizzmaniaa.vercel.app/auth/reset-password?secretcode=${userExist?._id
                }" class="reset-button">Reset Password</a>
                    <div class="warning">
                      This link will expire in 5 minutes for your security. If you didn’t request this, no action is required.
                    </div>
                  </div>
                  <div class="email-footer">
                    &copy; ${new Date().getFullYear()} QuizMania. All rights reserved.
                  </div>
                </div>
              </body>
            </html>
            `;

            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: process.env.GOOGLE_ACCOUNT_USER,
                    pass: process.env.GOOGLE_ACCOUNT_PASS,
                },
            });

            const info = await transporter.sendMail({
                from: `"QuizMania" <noreply@quizmania.com>`,
                to: email,
                subject: `Reset your QuizMania password`,
                html: html,
            });

            res.json({
                status: true,
                message: "Email send successfully, Check inbox or spam of email",
                email: email,
                info: info,
            });
        });

        // reset password request confirmation API
        app.patch("/reset-password/:id", async (req, res) => {
            try {
                const id = req.params.id;
                const { password } = req.body;

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });

                const expireUser = await expireCollection.findOne({
                    email: user?.email,
                });

                const now = new Date();
                const expiresAt = new Date(expireUser?.expiresAt);

                const fiveMinutesInMs = 1000 * 60 * 5;

                if (now.getTime() - expiresAt.getTime() > fiveMinutesInMs) {
                    res.json({ expired: true });
                    return;
                }

                if (!user) {
                    return res.status(404).json({
                        status: false,
                        message: "User not found",
                    });
                }

                const hashedPass = await bcrypt.hash(password, 10);

                const updateDoc = {
                    $set: { password: hashedPass },
                };

                await usersCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);

                res.json({
                    status: true,
                    message: "Password successfully changed",
                });
            } catch (err) {
                console.error("Reset password error:", err);
                res.status(500).json({
                    status: false,
                    message: "Internal server error",
                });
            }
        });

        // admin stats for showing data in admin dashboard API 
        app.get('/admin/stats', async (req, res) => {
            try {
                const users = await usersCollection.find().toArray();
                const quizzes = await quizzesCollection.find().toArray();
                const solvedQuizzes = await quizzesCollection.find({ status: "solved" }).toArray();

                const usersWithQuizCounts = await Promise.all(users.map(async (user) => {
                    const quizCount = await quizzesCollection.countDocuments({ user: user.email });
                    const lastActive = new Date(user.lastLoginTime);
                    const now = new Date();
                    const diffInHours = (now - lastActive) / (1000 * 60 * 60);
                    const userStatus = diffInHours > 24 ? "offline" : "online";
                    return {
                        ...user,
                        totalQuizzes: quizCount,
                        userStatus
                    };
                }));

                const quizzesWithAuthorName = await Promise.all(quizzes.map(async (quiz) => {
                    const author = await usersCollection.findOne({ email: quiz.user });
                    return {
                        ...quiz,
                        author: author?.username
                    };
                }));

                const now = new Date();
                const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
                const startOfNextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);

                // This works for both string and Date creationTime
                const monthWishUsers = await usersCollection.find({
                    $expr: {
                        $and: [
                            { $gte: [{ $dateFromString: { dateString: "$creationTime" } }, startOfMonth] },
                            { $lt: [{ $dateFromString: { dateString: "$creationTime" } }, startOfNextMonth] }
                        ]
                    }
                }).toArray();

                // Get quizzes solved this month
                const quizzesSolvedThisMonth = await quizzesCollection.find({
                    status: "solved",
                    $expr: {
                        $and: [
                            { $gte: [{ $dateFromString: { dateString: "$created" } }, startOfMonth] },
                            { $lt: [{ $dateFromString: { dateString: "$created" } }, startOfNextMonth] }
                        ]
                    }
                }).toArray();

                res.json({
                    status: true,
                    users: usersWithQuizCounts.length === 0 ? [] : usersWithQuizCounts,
                    quizzes: quizzesWithAuthorName.length === 0 ? [] : quizzesWithAuthorName,
                    solvedQuizzes: solvedQuizzes.length === 0 ? [] : solvedQuizzes,
                    monthWishUsers,
                    quizzesSolvedThisMonth,
                    startOfMonth,
                    startOfNextMonth
                });

            } catch (error) {
                console.error("Error fetching admin stats:", error);
                res.status(500).json({ status: false, message: "Server error" });
            }
        });

        // user stats for showing data in user dashboard API
        app.get("/user/stats/:email", async (req, res) => {
            const email = req.params.email;
            const totalQuiz = await quizzesCollection.find({ user: email }).toArray();

            const solvedQuiz = await quizzesCollection
                .find({ user: email, status: "solved" })
                .toArray();

            const totalCorrect = solvedQuiz.reduce(
                (sum, quiz) => sum + quiz.correctQuizAnswer,
                0
            );

            const totalPossible = solvedQuiz.reduce(
                (sum, quiz) => sum + quiz.parsedQuizData.length,
                0
            );

            const percentage = (totalCorrect / totalPossible) * 100;

            res.json({
                status: true,
                totalQuiz: totalQuiz.length === 0 ? [] : totalQuiz,
                solvedQuiz: solvedQuiz.length === 0 ? [] : solvedQuiz,
                averageMark: isNaN(parseFloat(percentage))
                    ? 0 + "%"
                    : parseInt(percentage) + "%",
            });
        });

        // Delete quiz API
        app.delete("/delete-quiz/:id", async (req, res) => {
            try {
                const id = req.params.id;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        status: false,
                        message: "Invalid quiz ID format",
                    });
                }

                const quizId = new ObjectId(id);
                const quiz = await quizzesCollection.findOne({ _id: quizId });

                if (!quiz) {
                    return res.status(404).json({
                        status: false,
                        message: "Quiz not found",
                    });
                }

                const result = await quizzesCollection.deleteOne({ _id: quizId });

                if (!result.acknowledged || result.deletedCount === 0) {
                    return res.status(500).json({
                        status: false,
                        message: "Failed to delete quiz",
                    });
                }

                res.json({
                    status: true,
                    message: "Quiz deleted successfully",
                });
            } catch (err) {
                console.error(`❌ Error deleting quiz with ID ${req.params.id}:`, err);
                res.status(500).json({
                    status: false,
                    message: "Internal server error",
                });
            }
        });

    } catch (error) {
        console.error("❌ MongoDB Connection Error:", error);
    }
}
run().catch(console.dir);

// Root route
app.get("/", (req, res) => {
    res.json({ message: "🚀 Yoo Server is running well!!" });
});

module.exports = app;
