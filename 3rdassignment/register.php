<?php
session_start(); // Start the session

$servername = "localhost"; 
$username = "user"; // Replace with your actual database username
$password = "cdcb"; // Replace with your actual database password
$dbname = "users"; 

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate input
    $username = htmlspecialchars(trim($_POST['username']));
    $email = htmlspecialchars(trim($_POST['email']));
    $phoneNumber = htmlspecialchars(trim($_POST['phone_number'])); // Updated name
    $password = htmlspecialchars(trim($_POST['password']));

    // Check for empty fields
    if (empty($username) || empty($email) || empty($phoneNumber) || empty($password)) {
        echo "All fields are required.";
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format.";
        exit;
    }

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Use prepared statements to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO users (username, email, phone_number, password) VALUES (?, ?, ?, ?)");
    if ($stmt === false) {
        die("Prepare failed: " . $conn->error);
    }

    $stmt->bind_param("ssss", $username, $email, $phoneNumber, $hashedPassword);

    if ($stmt->execute()) {
        // Registration successful, log the user in
        $_SESSION['username'] = $username; // Store username in session
        header("Location: loginpage.html"); // Redirect to the login page
        exit();
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close(); // Close the database connection
}
?>
