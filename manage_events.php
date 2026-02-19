<?php
include 'config.php';

try {
    $action = $_POST['action'] ?? '';

    // --- UPLOAD SECTION IMAGE (Form Submission) ---
    if ($action === 'upload_section_image') {
        if (!isset($_FILES['section_image']) || $_FILES['section_image']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("No file uploaded or upload error.");
        }

        $allowed = ['jpg', 'jpeg', 'png', 'webp'];
        $ext = strtolower(pathinfo($_FILES['section_image']['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed)) throw new Exception("Invalid file type. Only JPG, PNG, WEBP allowed.");

        $target = "uploads/events_section.jpg";
        if (!is_dir('uploads')) mkdir('uploads', 0777, true);

        if (move_uploaded_file($_FILES['section_image']['tmp_name'], $target)) {
            header("Location: content.php?success=ImageUpdated#events");
            exit;
        } else {
            throw new Exception("Failed to save file.");
        }
    }

    // --- JSON API RESPONSES BELOW ---
    header('Content-Type: application/json');

    if ($action === 'save') {
        $id = $_POST['id'] ?? '';
        $title = $_POST['title'] ?? '';
        $date = $_POST['event_date'] ?? '';
        $time = $_POST['event_time'] ?? '';
        $location = $_POST['location'] ?? '';

        if (empty($title) || empty($date)) throw new Exception("Title and Date are required.");

        if ($id) {
            $stmt = $conn->prepare("UPDATE events SET title=?, event_date=?, event_time=?, location=? WHERE id=?");
            $stmt->bind_param("ssssi", $title, $date, $time, $location, $id);
        } else {
            $stmt = $conn->prepare("INSERT INTO events (title, event_date, event_time, location) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $title, $date, $time, $location);
        }

        if ($stmt->execute()) echo json_encode(['success' => true]);
        else throw new Exception($stmt->error);
        $stmt->close();
        exit;
    }

    if ($action === 'delete') {
        $id = intval($_POST['id'] ?? 0);

        // 1. Fetch Event Data
        $res = $conn->query("SELECT * FROM events WHERE id=$id");
        if ($row = $res->fetch_assoc()) {
            // 2. Prepare Trash Data
            $trashName = $row['title'] . '|' . json_encode($row);

            // 3. Insert into Trash
            $stmt = $conn->prepare("INSERT INTO trash_bin (item_id, item_name, source, deleted_at) VALUES (?, ?, 'events', NOW())");
            $stmt->bind_param("is", $id, $trashName);
            $stmt->execute();
            $stmt->close();

            // 4. Delete from Events
            $conn->query("DELETE FROM events WHERE id=$id");
            echo json_encode(['success' => true]);
        } else {
            throw new Exception("Event not found");
        }
        exit;
    }

} catch (Exception $e) {
    // If headers not sent (e.g. upload error), redirect with error
    if (!headers_sent() && isset($_POST['action']) && $_POST['action'] === 'upload_section_image') {
        header("Location: content.php?error=" . urlencode($e->getMessage()) . "#events");
        exit;
    }
    // Otherwise return JSON
    if (!headers_sent()) header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
}
?>