// index.js
import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

// Basic route
app.get("/", (req, res) => {
  res.send("Liberation backend is running 🚀");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
