<?php
session_start(); // Start the session

$servername = "localhost"; 
$username = "root"; // Change if needed
$password = "cdcb"; // Change if needed
$dbname = "users"; 

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Debugging: Check if form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    echo "✅ Form submitted!<br>";

    $username = htmlspecialchars(trim($_POST['username']));
    $password = htmlspecialchars(trim($_POST['password']));

    echo "🔍 Entered Username: $username<br>";
    echo "🔍 Entered Password: $password<br>";

    // Check if username exists
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    if (!$stmt) {
        die("❌ Query preparation failed: " . $conn->error);
    }

    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    // If user exists, fetch password
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashedPasswordFromDatabase);
        $stmt->fetch();

        echo "✅ User found!<br>";
        echo "🔍 Stored Hash: $hashedPasswordFromDatabase<br>";

        // Verify the password
        if (password_verify($password, $hashedPasswordFromDatabase)) {
            echo "✅ Password matches!<br>";
            $_SESSION['username'] = $username;
            header("Location: dashboard.php"); // Redirect to a protected page
            exit();
        } else {
            echo "❌ Password does NOT match!<br>";
        }
    } else {
        echo "❌ No user found with that username.<br>";
    }

    $stmt->close();
}
$conn->close();
?>