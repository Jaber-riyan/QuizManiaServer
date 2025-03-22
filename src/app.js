require('dotenv').config();

const { GoogleGenerativeAI } = require('@google/generative-ai');
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require("bcrypt");

const app = express()
app.use(express.json())
app.use(morgan('dev'))
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://quizmania-chi.vercel.app'
    ],
    credentials: true
}))
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
    }
});

async function run() {
    try {
        console.log("✅ Successfully connected to MongoDB!");

        // Database
        const database = client.db('QuizMania')

        // Quizzes Collection
        const quizzesCollection = database.collection("quizzes")

        // Users Collection 
        const usersCollection = database.collection("users")

        // Create quiz API
        app.post('/generate-quiz', async (req, res) => {
            try {
                const { topic, difficulty, quantity, quizType } = req.body;

                // **Improved Prompting for Strict JSON Response**

                const prompt = `
                    Generate a ${difficulty} level quiz on "${topic}" with ${quizType} questions.
                    - Number of Questions: ${quantity}
                    - Return ONLY a valid JSON array. No extra text.
                    - Each question should have:
                        - "type": (Multiple Choice / True or False)
                        - "question": (Text of the question)
                        - "options": (Array of choices, only for multiple-choice)
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
                    parsedQuizData,
                    userEmail: "dummy@gmail.com",
                }

                const result = await quizzesCollection.insertOne(updatedData)

                // Send the response
                res.json({
                    // demo,
                    status: true,
                    message: "✅ Successfully generated quiz from AI",
                    quantity,
                    difficulty,
                    quizType,
                    topic,
                    quizzes: parsedQuizData,
                    result
                });

            } catch (err) {
                console.error("❌ Error generating quiz:", err);
                res.status(500).json({ status: false, message: err.message });
            }
        });

        // get the quiz set that user just created 
        app.get('/get-quiz-set/:id', async (req, res) => {
            const id = req.params.id;
            const result = await quizzesCollection.findOne({ _id: new ObjectId(id) });
            res.json(result);
        })

        // checking the quiz answer 
        app.post('/answer/checking', async (req, res) => {
            const { id, answers } = req.body;
            const quiz = await quizzesCollection.findOne({ _id: new ObjectId(id) });
            let score = 0;
            quiz.parsedQuizData.forEach((question, index) => {
                if (question.answer === answers[index]) {
                    score++;
                }
            })
            res.json({ score });
        })

        // stored user into the mongodb API 
        app.post('/register', async (req, res) => {
            const userData = req.body
            const userExist = await usersCollection.findOne({ email: userData.email })
            if (userExist) {
                res.json({ status: false, message: "User already exists" })
            } else {
                const result = await usersCollection.insertOne(userData)
                res.json({
                    status: true,
                    result
                })
            }

        })

    } catch (error) {
        console.error("❌ MongoDB Connection Error:", error);
    }
}
run().catch(console.dir);

// Root route
app.get('/', (req, res) => {
    res.json({ message: "🚀 Yoo Server is running well!!" });
});

module.exports = app;




// "text": "```json\n[\n  {\n    \"type\": \"Multiple Choice\",\n    \"question\": \"What keyword is used to define a function in Python?\",\n    \"options\": [\"def\", \"function\", \"define\", \"func\"],\n    \"answer\": \"def\"\n  },\n  {\n    \"type\": \"Multiple Choice\",\n    \"question\": \"Which of the following is NOT a built-in data type in Python?\",\n    \"options\": [\"Integer\", \"String\", \"Float\", \"Character\"],\n    \"answer\": \"Character\"\n  }\n]\n```"


// "quizzes": [
//         {
//             "type": "Multiple Choice",
//             "question": "What keyword is used to define a function in Python?",
//             "options": [
//                 "def",
//                 "function",
//                 "define",
//                 "func"
//             ],
//             "answer": "def"
//         },
//         {
//             "type": "Multiple Choice",
//             "question": "Which of the following is NOT a built-in data type in Python?",
//             "options": [
//                 "Integer",
//                 "String",
//                 "Float",
//                 "Character"
//             ],
//             "answer": "Character"
//         }
//     ]