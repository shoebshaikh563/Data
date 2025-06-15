import express from "express";
import fs from "fs";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(express.json()); // Parses incoming JSON requests
app.use(express.urlencoded({ extended: true })); // Parses form data
const usersFile = "./db.json";

const readUsers = () => {
  const data = fs.readFileSync(usersFile, "utf-8");
  return JSON.parse(data);
};

const writeUsers = (users) => {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
};

app.get("/", (req, res) => {
  res.send("Hello");
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = data;
    next();
  });
}

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const user = readUsers();
  const existingUser = user.find((u) => u.username == username);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  user.push({ username, password: hashedPassword });
  writeUsers(user);
  res.status(201).json({ message: "User registered successfully" });
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ message: "Invalid credentials" });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });
  const token = jwt.sign({ username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res.json({ message: "Login successful", token });
});

app.get("/user", verifyToken, (req, res) => {
  const username = req.user.username;
  res.status(200).send({ message: "user is logedin", username });
});

app.listen(3000, () => {
  console.log("Express server is running at http://localhost:3000");
});
