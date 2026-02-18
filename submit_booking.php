<?php
session_start();
require __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Invalid request method.");
}

// Ensure logged in
if (!isset($_SESSION['username'])) {
    die("You must be logged in to book.");
}

// Get logged in user's ID
$stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE username = ? LIMIT 1");
if (!$stmt) {
    die("Prepare failed: " . mysqli_error($conn));
}
mysqli_stmt_bind_param($stmt, "s", $_SESSION['username']);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($res);
if (!$user) {
    die("Logged-in user not found.");
}
$user_id = (int) $user['id'];

// Collect and validate booking data
$artwork_id = isset($_POST['artwork_id']) ? (int)$_POST['artwork_id'] : null;
$service = $_POST['service'] ?? ''; 
$preferred_date = $_POST['preferred_date'] ?? null;
$full_name = $_POST['full_name'] ?? '';
$phone_number = $_POST['phone_number'] ?? '';
$special_requests = $_POST['special_requests'] ?? '';

// Legacy fields (optional)
$vehicle_type = $_POST['vehicle_type'] ?? '';
$vehicle_model = $_POST['vehicle_model'] ?? '';

// --- HANDLE VALID ID UPLOAD ---
$valid_id_image = null;
if (isset($_FILES['valid_id']) && $_FILES['valid_id']['error'] === UPLOAD_ERR_OK) {
    $uploadDir = 'uploads/';
    // Create directory if it doesn't exist
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $fileTmpPath = $_FILES['valid_id']['tmp_name'];
    $fileName = $_FILES['valid_id']['name'];
    $fileSize = $_FILES['valid_id']['size'];
    $fileType = $_FILES['valid_id']['type'];
    
    // Generate unique filename
    $newFileName = time() . '_id_' . $fileName;
    $dest_path = $uploadDir . $newFileName;

    if(move_uploaded_file($fileTmpPath, $dest_path)) {
        $valid_id_image = $newFileName;
    }
}
// -----------------------------

// Updated Insert Query to include valid_id_image
$sql = "INSERT INTO bookings (user_id, artwork_id, service, vehicle_type, vehicle_model, preferred_date, full_name, phone_number, special_requests, valid_id_image, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())";

$stmt = mysqli_prepare($conn, $sql);
if (!$stmt) {
    die("Prepare failed: " . mysqli_error($conn));
}

// Type definition: i = integer, s = string
// user_id(i), artwork_id(i), service(s), vehicle_type(s), vehicle_model(s), preferred_date(s), full_name(s), phone_number(s), special_requests(s), valid_id_image(s)
mysqli_stmt_bind_param($stmt, "iissssssss",
    $user_id, $artwork_id, $service, $vehicle_type, $vehicle_model, $preferred_date,
    $full_name, $phone_number, $special_requests, $valid_id_image
);

if (!mysqli_stmt_execute($stmt)) {
    die("Insert failed: " . mysqli_stmt_error($stmt));
}

// Redirect back with success message
if ($artwork_id) {
    header("Location: collection.php?success=1");
} else {
    header("Location: index.php?success=1");
}
exit;
?>