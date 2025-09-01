import React from "react";
import { createRoot } from "react-dom/client";

function App() {
  return <h1>Hello, Liberation Frontend is working!</h1>;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
