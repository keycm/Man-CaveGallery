<?php
session_start();
include 'config.php';
require_once __DIR__ . '/reset_mailer.php'; 

// =================================================================
// 1. AUTHENTICATION & ACCOUNT LOGIC
// =================================================================

// --- AJAX HANDLER FOR FORGOT PASSWORD FLOW ---
if (isset($_POST['ajax_action'])) {
    header('Content-Type: application/json');
    $action = $_POST['ajax_action'];
    $response = ['status' => 'error', 'message' => 'An error occurred.'];

    try {
        if ($action === 'send_reset_otp') {
            $email = $_POST['email'] ?? '';
            $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res->num_rows > 0) {
                $user = $res->fetch_assoc();
                $otp = random_int(100000, 999999);
                $otp_hash = hash("sha256", $otp); 
                $expiry = date("Y-m-d H:i:s", time() + 60 * 15);
                $update = $conn->prepare("UPDATE users SET reset_token_hash = ?, reset_token_expires_at = ? WHERE id = ?");
                $update->bind_param("ssi", $otp_hash, $expiry, $user['id']);
                if ($update->execute()) {
                    $mail = require __DIR__ . '/reset_mailer.php';
                    $mail->setFrom("noreply@example.com", "ManCave Gallery");
                    $mail->addAddress($email);
                    $mail->Subject = "Password Reset OTP";
                    $mail->isHTML(true);
                    $mail->Body = "<h3>Password Reset Request</h3><p>Hi " . htmlspecialchars($user['username']) . ",</p><p>Your OTP code is:</p><h2 style='background:#eee;padding:10px;display:inline-block;'>$otp</h2><p>Expires in 15 mins.</p>";
                    $mail->send();
                    $response = ['status' => 'success', 'message' => 'OTP sent to your email.'];
                }
            } else {
                $response = ['status' => 'error', 'message' => 'Email not found.'];
            }
        } 
        elseif ($action === 'verify_reset_otp') {
            $email = $_POST['email'] ?? '';
            $otp = $_POST['otp'] ?? '';
            $otp_hash = hash("sha256", $otp);
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND reset_token_hash = ? AND reset_token_expires_at > NOW()");
            $stmt->bind_param("ss", $email, $otp_hash);
            $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                $response = ['status' => 'success', 'message' => 'OTP verified.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Invalid or expired OTP.'];
            }
        }
        elseif ($action === 'reset_password') {
            $email = $_POST['email'] ?? '';
            $otp = $_POST['otp'] ?? '';
            $new_pass = $_POST['new_password'] ?? '';
            $confirm_pass = $_POST['confirm_password'] ?? '';
            $otp_hash = hash("sha256", $otp);
            if ($new_pass !== $confirm_pass) {
                $response = ['status' => 'error', 'message' => 'Passwords do not match.'];
            } elseif (strlen($new_pass) < 8) {
                $response = ['status' => 'error', 'message' => 'Password must be at least 8 characters.'];
            } else {
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND reset_token_hash = ? AND reset_token_expires_at > NOW()");
                $stmt->bind_param("ss", $email, $otp_hash);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $new_hash = password_hash($new_pass, PASSWORD_DEFAULT);
                    $update = $conn->prepare("UPDATE users SET password = ?, reset_token_hash = NULL, reset_token_expires_at = NULL WHERE email = ?");
                    $update->bind_param("ss", $new_hash, $email);
                    if ($update->execute()) {
                        $response = ['status' => 'success', 'message' => 'Password reset successfully.'];
                    }
                } else {
                    $response = ['status' => 'error', 'message' => 'Session expired. Please try again.'];
                }
            }
        }
    } catch (Exception $e) {
        $response = ['status' => 'error', 'message' => 'Server error: ' . $e->getMessage()];
    }
    echo json_encode($response);
    exit;
}

// --- ACCOUNT VERIFICATION LOGIC (OTP) ---
if (isset($_POST['verify_account'])) {
    $otp_input = trim($_POST['otp']);
    $email = $_SESSION['otp_email'] ?? '';
    if (empty($email)) {
        $_SESSION['error_message'] = "Session expired. Please sign up again.";
    } elseif (empty($otp_input)) {
        $_SESSION['error_message'] = "Please enter the code.";
        $_SESSION['show_verify_modal'] = true; 
    } else {
        $stmt = $conn->prepare("SELECT id, account_activation_hash, reset_token_expires_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user_res = $stmt->get_result();
        $user = $user_res->fetch_assoc();
        if (!$user) {
            $_SESSION['error_message'] = "Account not found.";
        } elseif ($user['account_activation_hash'] == NULL) {
            $_SESSION['success_message'] = "Account already verified. Please Login.";
            unset($_SESSION['otp_email']);
            header("Location: about.php?login=1");
            exit;
        } else {
            $expiry = strtotime($user['reset_token_expires_at']);
            $db_otp = (string)$user['account_activation_hash'];
            $input_otp = (string)$otp_input;
            if (time() > $expiry) {
                $_SESSION['error_message'] = "Code expired. Please register again.";
            } elseif ($db_otp !== $input_otp) {
                $_SESSION['error_message'] = "Incorrect code. Try again.";
                $_SESSION['show_verify_modal'] = true; 
            } else {
                $upd = $conn->prepare("UPDATE users SET account_activation_hash = NULL, reset_token_expires_at = NULL WHERE id = ?");
                $upd->bind_param("i", $user['id']);
                if ($upd->execute()) {
                    $_SESSION['success_message'] = "You are successfully registered";
                    unset($_SESSION['otp_email']);
                    unset($_SESSION['show_verify_modal']);
                    header("Location: about.php");
                    exit;
                } else {
                    $_SESSION['error_message'] = "Database error.";
                }
            }
        }
    }
    header("Location: about.php");
    exit;
}

// --- LOGIN LOGIC ---
if (isset($_POST['login'])) {     
    $identifier = $_POST['identifier'];     
    $password = $_POST['password'];      
    $sql = "SELECT * FROM users WHERE username=? OR email=? LIMIT 1";     
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "ss", $identifier, $identifier);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);     
    if ($result && mysqli_num_rows($result) === 1) {
        $row = mysqli_fetch_assoc($result);
        if (!empty($row['account_activation_hash'])) {
            $_SESSION['error_message'] = "Account not activated. Enter the code sent to your email.";
            $_SESSION['otp_email'] = $row['email'];
            $_SESSION['show_verify_modal'] = true; 
            header("Location: about.php");
            exit();
        }
        if (password_verify($password, $row['password'])) {
            $_SESSION['username'] = $row['username'];
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['role'] = $row['role'];
            header("Location: " . ($row['role'] == 'admin' ? 'admin.php' : 'about.php'));
            exit();
        } else {
            $_SESSION['error_message'] = "Invalid password!";
        }
    } else {
        $_SESSION['error_message'] = "User not found!";
    }
    if(isset($_SESSION['error_message'])) {
        header("Location: about.php?login=1");
        exit();
    }
} 

// --- SIGNUP LOGIC ---
if (isset($_POST['sign'])) {
    $name = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    if (empty($name) || empty($email) || empty($password)) {
        $_SESSION['error_message'] = "All fields are required!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error_message'] = "Valid email is required!";
    } elseif (strlen($password) < 8) {
        $_SESSION['error_message'] = "Password must be at least 8 characters!";
    } elseif ($password !== $confirm_password) {
        $_SESSION['error_message'] = "Passwords do not match!";
    } else {
        $check_sql = "SELECT id FROM users WHERE email = ?";
        $stmt = $conn->prepare($check_sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $_SESSION['error_message'] = "Email already registered!";
        } else {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $otp = random_int(100000, 999999);
            $otp_expiry = date("Y-m-d H:i:s", time() + 60 * 10); 
            $sql = "INSERT INTO users (username, email, password, account_activation_hash, reset_token_expires_at) VALUES (?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            if ($stmt) {
                $stmt->bind_param("sssss", $name, $email, $password_hash, $otp, $otp_expiry);
                if ($stmt->execute()) {
                    $mail->setFrom("noreply@example.com", "ManCave Gallery");
                    $mail->addAddress($email);
                    $mail->Subject = "Account Activation OTP";
                    $mail->isHTML(true);
                    $mail->Body = "<h3>Welcome to ManCave!</h3><p>Your activation code is: <b style='font-size:1.2em'>$otp</b></p>";
                    try {
                        $mail->send();
                        $_SESSION['otp_email'] = $email;
                        $_SESSION['success_message'] = "Registration successful! Check your email for the code.";
                        $_SESSION['show_verify_modal'] = true; 
                        header("Location: about.php"); 
                        exit;
                    } catch (Exception $e) {
                        $_SESSION['error_message'] = "Mailer Error: " . $mail->ErrorInfo;
                    }
                } else {
                    $_SESSION['error_message'] = "Database Error.";
                }
            }
        }
    }
    if(isset($_SESSION['error_message'])) {
        header("Location: about.php?signup=1");
        exit();
    }
}

// Check login status for Navbar logic
$loggedIn = isset($_SESSION['username']);

// === FETCH USER DATA (Profile Pic) ===
$user_profile_pic = ""; 
if ($loggedIn && isset($_SESSION['user_id'])) {
    $uid = $_SESSION['user_id'];
    $user_sql = "SELECT username, image_path FROM users WHERE id = $uid"; 
    $user_res = mysqli_query($conn, $user_sql);
    
    if ($user_data = mysqli_fetch_assoc($user_res)) {
        if (!empty($user_data['image_path'])) {
            $user_profile_pic = 'uploads/' . $user_data['image_path'];
        } else {
            $user_profile_pic = "https://ui-avatars.com/api/?name=" . urlencode($user_data['username']) . "&background=cd853f&color=fff&rounded=true&bold=true";
        }
    }
}

// === FETCH ARTISTS/TEAM ===
$team_members = [];
$team_sql = "SELECT * FROM about_artists ORDER BY id ASC";
$team_res = mysqli_query($conn, $team_sql);
if ($team_res) {
    while ($row = mysqli_fetch_assoc($team_res)) {
        $team_members[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About Us | ManCave Gallery</title>
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@300;400;600;700;800&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    
    <style>
         /* =========================================
           UI VARIABLES & RESET
           ========================================= */
        :root {
            /* Default Light Mode Variables Only */
            --bg-body: #ffffff;
            --bg-card: #ffffff;
            --bg-section: #f8f5f2;
            --text-main: #2c2c2c;
            --text-sec: #666666;
            --border-color: #e0e0e0;
            --nav-scrolled-bg: rgba(255, 255, 255, 0.98);
            --nav-text: #2c2c2c;
            --modal-bg: #ffffff;
            --input-bg: #f8f9fa;
            
            --primary: #333333;       
            --secondary: #666666;     
            --accent-orange: #f36c21;
            --brand-red: #ff4d4d;
            --bg-light: #ffffff;      
            --font-main: 'Nunito Sans', sans-serif;       
            --font-head: 'Playfair Display', serif; 
            --font-script: 'Pacifico', cursive;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        /* === FIXED: OVERFLOW PREVENTION === */
        html, body {
            width: 100%;
            max-width: 100vw;
            overflow-x: hidden;
            background-color: var(--bg-body);
            color: var(--text-sec);
        }

        body {
            font-family: var(--font-main);
            line-height: 1.6;
            font-size: 0.95rem;
        }
        
        h1, h2, h3, h4, h5 { color: var(--text-main) !important; }
        .bg-light { background-color: var(--bg-section) !important; }
        .bg-white { background-color: var(--bg-card) !important; }

        a { text-decoration: none; color: inherit; transition: all 0.3s ease; }
        ul { list-style: none; }

        /* =========================================
           NAVBAR (FIXED WHITE BACKGROUND)
           ========================================= */
        .navbar {
            position: fixed; top: 0; width: 100%;
            background: #ffffff; /* FORCE WHITE BACKGROUND */
            padding: 15px 0;
            z-index: 1000; 
            border-bottom: 1px solid #eee;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05); /* Added shadow for visibility */
            transition: 0.3s;
        }
        .navbar.scrolled { 
            padding: 10px 0; /* Shrink on scroll */
        }

        .nav-container { display: flex; justify-content: space-between; align-items: center; max-width: 1140px; margin: 0 auto; padding: 0 20px; }

        .logo { text-decoration: none; display: flex; gap: 8px; align-items: baseline; line-height: 1; white-space: nowrap; }
        .logo:hover { transform: scale(1.02); }
        .logo-top { font-family: var(--font-head); font-size: 1rem; font-weight: 700; color: var(--primary); letter-spacing: 1px; margin-bottom: 0; }
        .logo-main { font-family: var(--font-script); font-size: 1.8rem; font-weight: 400; transform: rotate(-2deg); margin: 0; padding: 0; }
        .logo-red { color: #8B0000; }
        .logo-text { color: var(--primary); }
        .logo-bottom { font-family: var(--font-main); font-size: 0.85rem; font-weight: 800; color: var(--primary); letter-spacing: 2px; text-transform: uppercase; margin: 0; }

        .nav-links { display: flex; gap: 30px; }
        .nav-links a { font-weight: 700; color: var(--primary); font-size: 1rem; position: relative; transition: color 0.3s; }
        .nav-links a:hover, .nav-links a.active { color: var(--accent-orange); }

        .btn-nav { background: var(--primary); color: var(--bg-body); padding: 10px 25px; border-radius: 50px; border: none; cursor: pointer; font-weight: 700; margin-left: 15px; font-size: 0.9rem; transition: 0.3s; box-shadow: 0 3px 8px rgba(0,0,0,0.15); }
        .btn-nav:hover { background: var(--accent-orange); color: white; }
        .btn-nav-outline { background: transparent; color: var(--primary); border: 2px solid var(--primary); padding: 8px 20px; border-radius: 50px; font-weight: 700; cursor: pointer; font-size: 0.9rem; transition: 0.3s; }
        .btn-nav-outline:hover { background: var(--primary); color: var(--bg-body); }

        /* Header Icons & Profile */
        .nav-actions { display: flex; align-items: center; gap: 15px; }
        .header-icon-btn {
            background: #f8f8f8; border: 1px solid #eee; width: 40px; height: 40px;
            border-radius: 50%; display: flex; align-items: center; justify-content: center;
            color: var(--primary); font-size: 1.1rem; cursor: pointer; transition: all 0.3s ease; position: relative;
        }
        .header-icon-btn:hover { background: #fff; box-shadow: 0 4px 10px rgba(0,0,0,0.1); color: var(--accent-orange); }
        
        .notif-badge { position: absolute; top: -2px; right: -2px; background: var(--brand-red); color: white; font-size: 0.65rem; font-weight: bold; padding: 2px 5px; border-radius: 50%; min-width: 18px; text-align: center; border: 2px solid #fff; }
        
        .profile-pill { display: flex; align-items: center; gap: 10px; background: #f8f8f8; padding: 4px 15px 4px 4px; border-radius: 50px; border: 1px solid #eee; cursor: pointer; transition: all 0.3s ease; }
        .profile-pill:hover { background: #fff; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .profile-img { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; border: 2px solid var(--accent-orange); }
        .profile-name { font-weight: 700; font-size: 0.9rem; color: var(--primary); padding-right: 5px; }

        /* Dropdowns */
        .user-dropdown, .notification-wrapper { position: relative; }
        .dropdown-content, .notif-dropdown { display: none; position: absolute; top: 140%; right: 0; background: var(--bg-card); box-shadow: 0 5px 15px rgba(0,0,0,0.1); border-radius: 8px; z-index: 1001; border: 1px solid #eee; }
        .dropdown-content { min-width: 180px; padding: 10px 0; }
        .notif-dropdown { width: 320px; right: -10px; top: 160%; }
        .user-dropdown.active .dropdown-content, .notif-dropdown.active { display: block; animation: fadeIn 0.2s ease-out; }
        
        .dropdown-content a { display: block; padding: 10px 20px; color: var(--text-main); font-size: 0.9rem; }
        .dropdown-content a:hover { background: var(--input-bg); color: var(--accent-orange); }
        
        .notif-header { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; font-weight: 700; background: var(--input-bg); font-size: 0.9rem; color: var(--text-main); }
        .notif-list { max-height: 300px; overflow-y: auto; list-style: none; padding: 0; margin: 0; }
        .notif-item { padding: 15px 35px 15px 15px; border-bottom: 1px solid #eee; font-size: 0.9rem; cursor: pointer; position: relative; display: flex; flex-direction: column; gap: 5px; color: var(--text-main); }
        .notif-item:hover { background: var(--input-bg); }
        .notif-item.unread { background: #fff8f0; border-left: 4px solid var(--accent-orange); }
        .notif-msg { color: var(--text-main); line-height: 1.4; }
        .notif-time { font-size: 0.75rem; color: var(--text-sec); font-weight: 600; }
        .btn-notif-close { position: absolute; top: 10px; right: 10px; background: none; border: none; color: #aaa; font-size: 1.2rem; line-height: 1; cursor: pointer; padding: 0; transition: color 0.2s; }
        .btn-notif-close:hover { color: #ff4d4d; }
        .no-notif { padding: 30px; text-align: center; color: var(--text-sec); font-style: italic; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: translateY(0); } }

        /* Modal Styles */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(5px); display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; padding: 20px; }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        .modal-card { background: var(--modal-bg); padding: 30px; border-radius: 12px; width: 550px; max-width: 100%; max-height: 90vh; overflow-y: auto; position: relative; transform: translateY(20px); transition: 0.3s; box-shadow: 0 15px 50px rgba(0,0,0,0.4); display: flex; flex-direction: column; }
        .modal-overlay.active .modal-card { transform: translateY(0); }
        .modal-close { position: absolute; top: 15px; right: 20px; background: none; border: none; font-size: 1.8rem; cursor: pointer; color: #999; transition: 0.2s; z-index: 10; }
        .modal-close:hover { color: #333; transform: rotate(90deg); }
        .modal-card.small { width: 420px; max-width: 95%; padding: 45px 35px; align-items: center; text-align: center; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
        .modal-header-icon { font-size: 3rem; color: var(--accent-orange); margin-bottom: 20px; background: rgba(243, 108, 33, 0.1); width: 80px; height: 80px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; }
        .friendly-input-group { position: relative; margin-bottom: 20px; text-align: left; width: 100%; }
        .friendly-input-group i { position: absolute; top: 50%; left: 20px; transform: translateY(-50%); color: #bbb; font-size: 1.1rem; pointer-events: none; transition: 0.3s; }
        .friendly-input-group input { width: 100%; padding: 14px 14px 14px 55px; border-radius: 50px; background: var(--input-bg); border: 1px solid var(--border-color); font-size: 0.95rem; transition: all 0.3s ease; outline: none; color: var(--text-main); }
        .friendly-input-group input:focus { background: var(--bg-card); border-color: var(--accent-orange); box-shadow: 0 4px 15px rgba(243, 108, 33, 0.15); }
        .btn-friendly { width: 100%; padding: 15px; border-radius: 50px; border: none; background: linear-gradient(135deg, var(--accent-orange), #ff8c42); color: #fff; font-weight: 800; font-size: 1rem; cursor: pointer; transition: 0.3s; margin-top: 10px; box-shadow: 0 4px 15px rgba(243, 108, 33, 0.3); }
        .btn-friendly:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(243, 108, 33, 0.4); }
        .modal-footer-link { text-align: center; margin-top: 15px; font-size: 0.95rem; color: var(--text-sec); }
        .modal-footer-link a { color: var(--accent-orange); font-weight: 700; }
        .forgot-pass-link { text-decoration: none; color: #888; font-size: 0.85rem; font-weight: 600; transition: color 0.3s ease; }
        .alert-error { background: #ffe6e6; color: #d63031; padding: 12px; border-radius: 12px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid #fab1a0; width: 100%; }

        /* === BURGER MENU & RESPONSIVE === */
        .mobile-menu-icon { display: none; font-size: 1.6rem; cursor: pointer; color: var(--primary); margin-left: 15px; } /* Fixed color */

        @media (max-width: 768px) {
            .navbar { background: #ffffff; padding: 12px 0; border-bottom: 1px solid #eee; }
            .nav-container { padding: 0 15px; position: relative; justify-content: space-between; }
            
            .logo { display: flex; flex-direction: column; align-items: center; line-height: 1; }
            .logo-main { font-size: 1.4rem !important; transform: rotate(0deg) !important; margin: 2px 0 !important; }
            .logo-top { font-size: 0.7rem; }
            .logo-bottom { font-size: 0.6rem; }
            .logo-text { color: var(--primary); } 
            .logo-top, .logo-bottom { color: var(--primary); }
            
            .navbar.scrolled .logo { flex-direction: column; align-items: center; gap: 0; }
            .navbar.scrolled .logo-main { font-size: 1.4rem; transform: rotate(0deg); padding: 0; }
            .navbar.scrolled .logo-top { font-size: 0.7rem; }
            .navbar.scrolled .logo-bottom { font-size: 0.6rem; }

            .nav-links { 
                display: none; 
                position: absolute; 
                top: 100%; left: 0; width: 100%; 
                background: #ffffff; 
                flex-direction: column; 
                gap: 0; 
                box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                padding: 0;
                animation: fadeIn 0.3s ease;
            }
            .nav-links.active { display: flex; }
            .nav-links li { width: 100%; border-bottom: 1px solid #f5f5f5; }
            .nav-links a { display: block; padding: 15px 20px; color: var(--primary); text-align: center; }
            
            .nav-actions { gap: 8px; align-items: center; }
            .header-icon-btn { background: #f8f8f8; border-color: #eee; color: var(--primary); width: 35px; height: 35px; font-size: 1rem; }
            .notif-badge { border-color: #fff; }

            .profile-pill { 
                padding: 0; border: none; background: transparent; 
                width: 35px; height: 35px; 
                justify-content: center; 
            }
            .profile-pill:hover { background: transparent; }
            .profile-name, .profile-pill .fa-chevron-down { display: none; } 
            .profile-img { 
                width: 35px; height: 35px; 
                border: 2px solid var(--accent-orange); 
            }

            .mobile-menu-icon { display: block; color: var(--primary); }
            .page-header h1 { font-size: 2.5rem; }
        }

        /* === PAGE SPECIFIC STYLES === */
        .page-header {
            background: linear-gradient(rgba(0,0,0,0.5), rgba(0,0,0,0.7)), url('Grand Opening - Man Cave Gallery/img-12.jpg');
            background-size: cover;
            background-position: center;
            height: 60vh;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            color: white;
            margin-bottom: 80px;
        }
        
        .page-header h1 { font-size: 3.5rem; color: white !important; margin-bottom: 10px; font-family: var(--font-head); }
        .page-header p { font-size: 1.2rem; max-width: 600px; margin: 0 auto; opacity: 0.9; color: rgba(255,255,255,0.9); }

        .story-text { font-size: 1.1rem; line-height: 1.8; color: var(--text-sec); margin-bottom: 20px; }
        
        .stats-row {
            display: flex; justify-content: space-between;
            margin-top: 50px; text-align: center;
            border-top: 1px solid #eee; padding-top: 40px;
        }
        .stat-item h3 { font-size: 2.5rem; color: var(--accent-orange) !important; margin-bottom: 5px; font-family: var(--font-head); }
        .stat-item p { font-weight: 700; color: var(--text-main); text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; }

        .team-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px; margin-top: 50px;
        }
        .team-member { text-align: center; }
        .team-img { width: 100%; height: 350px; object-fit: cover; border-radius: 8px; margin-bottom: 20px; filter: grayscale(100%); transition: 0.3s; }
        .team-member:hover .team-img { filter: grayscale(0%); transform: translateY(-5px); }
        .team-name { font-weight: 700; font-size: 1.2rem; color: var(--text-main); margin-bottom: 5px; }
        .team-role { color: var(--accent-orange); font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        
        /* Footer Styles from Index */
        footer { background: #1a1a1a; color: #bbb; padding: 80px 0 30px; margin-top: auto; font-size: 0.95rem; }
        .footer-grid { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 50px; margin-bottom: 50px; }
        .footer-about h3 { color: #fff; margin-bottom: 20px; font-family: var(--font-head); font-size: 1.6rem; }
        .footer-logo { display: flex; flex-direction: row; gap: 8px; align-items: center; margin-bottom: 15px; }
        .footer-logo .logo-top { font-size: 1.8rem; margin-bottom: 0; }
        .footer-logo .logo-main { font-size: 2.4rem; margin: 0; padding: 0; }
        .footer-logo .logo-bottom { font-size: 1.8rem; margin-top: 0; letter-spacing: 1px; }
        .socials a { display: inline-flex; width: 40px; height: 40px; background: #333; color: #fff; align-items: center; justify-content: center; border-radius: 50%; margin-right: 10px; transition: 0.3s; font-size: 1.1rem; }
        .socials a:hover { background: var(--accent-orange); transform: translateY(-3px); }
        .footer-links h4, .footer-contact h4 { color: #fff; margin-bottom: 20px; font-size: 1.1rem; }
        .footer-links ul li { margin-bottom: 12px; }
        .footer-links a:hover { color: var(--accent-orange); padding-left: 5px; }
        .footer-contact p { margin-bottom: 12px; display: flex; gap: 12px; align-items: flex-start; }
        .footer-contact i { color: var(--accent-orange); margin-top: 4px; }
        .footer-bottom { border-top: 1px solid #333; padding-top: 25px; text-align: center; font-size: 0.85rem; }
    </style>
</head>
<body>

    <nav class="navbar">
        <div class="container nav-container">
            <a href="./" class="logo"> <span class="logo-top">THE</span>
                <span class="logo-main">
                    <span class="logo-red">M</span><span class="logo-text">an</span><span class="logo-red">C</span><span class="logo-text">ave</span>
                </span>
                <span class="logo-bottom">GALLERY</span>
            </a>
            <ul class="nav-links" id="navLinks">
                <li><a href="index.php">Home</a></li>
                <li><a href="collection">Collection</a></li>
                <li><a href="index.php#artists">Artists</a></li>
                <li><a href="index.php#services">Services</a></li>
                <li><a href="index.php#contact-form">Visit</a></li>
            </ul>
            <div class="nav-actions">
                <?php if ($loggedIn): ?>
                    <a href="favorites" class="header-icon-btn" title="My Favorites"> <i class="far fa-heart"></i>
                    </a>
                    <div class="notification-wrapper">
                        <button class="header-icon-btn" id="notifBtn" title="Notifications">
                            <i class="far fa-bell"></i>
                            <span class="notif-badge" id="notifBadge" style="display:none;">0</span>
                        </button>
                        <div class="notif-dropdown" id="notifDropdown">
                            <div class="notif-header">
                                <span>Notifications</span>
                                <button id="markAllRead" class="small-btn">Mark all read</button>
                            </div>
                            <ul class="notif-list" id="notifList">
                                <li class="no-notif">Loading...</li>
                            </ul>
                        </div>
                    </div>
                    <div class="user-dropdown">
                        <div class="profile-pill">
                            <img src="<?php echo htmlspecialchars($user_profile_pic); ?>" alt="Profile" class="profile-img">
                            <span class="profile-name"><?php echo htmlspecialchars($_SESSION['username']); ?></span>
                            <i class="fas fa-chevron-down" style="font-size: 0.7rem; color: rgba(255,255,255,0.7);"></i>
                        </div>
                        <div class="dropdown-content">
                            <?php if(isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                                <a href="admin"><i class="fas fa-cog"></i> Dashboard</a> <?php endif; ?>
                            <a href="profile"><i class="fas fa-user-cog"></i> Profile Settings</a> <a href="logout"><i class="fas fa-sign-out-alt"></i> Logout</a> </div>
                    </div>
                <?php else: ?>
                    <button id="openSignupBtn" class="btn-nav-outline">Sign Up</button>
                    <button id="openLoginBtn" class="btn-nav">Sign In</button>
                <?php endif; ?>
                
                <div class="mobile-menu-icon" onclick="toggleMobileMenu()"><i class="fas fa-bars"></i></div>
            </div>
        </div>
    </nav>

    <header class="page-header">
        <div class="container" data-aos="fade-up">
            <h1>Our Story</h1>
            <p>From a passion project to a premier destination for contemporary art.</p>
        </div>
    </header>

    <section class="section-padding">
        <div class="container">
            <div class="row">
                <div class="col-6 content-padding" data-aos="fade-right">
                    <h4 class="section-tag">Who We Are</h4>
                    <h2 class="section-title">More Than Just a Gallery</h2>
                    <p class="story-text">
                        Founded in 2020, ManCave Gallery began with a simple idea: art should be experienced, not just viewed. We set out to create a sanctuary where the raw energy of modern masculinity meets the refined elegance of fine art.
                    </p>
                    <p class="story-text">
                        Located in the heart of Pampanga, our space is designed to be an escape from the ordinary. We specialize in contemporary realism, abstract expressionism, and modern sculpture, curating pieces that tell bold stories and evoke powerful emotions.
                    </p>
                    <div class="stats-row">
                        <div class="stat-item">
                            <h3>500+</h3>
                            <p>Artworks Sold</p>
                        </div>
                        <div class="stat-item">
                            <h3>50+</h3>
                            <p>Artists Represented</p>
                        </div>
                        <div class="stat-item">
                            <h3>4</h3>
                            <p>Years of Excellence</p>
                        </div>
                    </div>
                </div>
                <div class="col-6" data-aos="fade-left">
                    <div class="image-stack" style="height: 550px;">
                        <img src="https://images.unsplash.com/photo-1577720580479-7d839d829c73?q=80&w=800&auto=format&fit=crop" class="img-back" style="height: 100%; width: 90%;">
                        <img src="Grand Opening - Man Cave Gallery/img-10.jpg" class="img-front" style="height: 300px; bottom: -40px; right: -20px;">
                    </div>
                </div>
            </div>
        </div>
    </section>

    <section class="section-padding bg-light">
        <div class="container text-center" data-aos="fade-up">
            <h4 class="section-tag">Our Vision</h4>
            <h2 class="section-title mb-5">Curating the Future</h2>
            <p style="max-width: 800px; margin: 0 auto; font-size: 1.2rem; color: var(--text-sec);">
                "We envision a world where art is accessible, personal, and transformative. Our mission is to connect collectors with pieces that do more than decorate a room—they define it."
            </p>
        </div>
    </section>

    <section class="section-padding">
        <div class="container">
            <div class="text-center mb-5">
                <h4 class="section-tag">The Talent</h4>
                <h2 class="section-title">Meet the Artists</h2>
            </div>
            
            <div class="team-grid">
                <?php if (empty($team_members)): ?>
                    <div class="team-member" data-aos="fade-up" data-aos-delay="100">
                        <img src="https://images.unsplash.com/photo-1560250097-0b93528c311a?q=80&w=400&auto=format&fit=crop" alt="Artist" class="team-img">
                        <div class="team-name">Alexander Ford</div>
                        <div class="team-role">Founder & Lead Artist</div>
                    </div>
                    <div class="team-member" data-aos="fade-up" data-aos-delay="200">
                        <img src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?q=80&w=400&auto=format&fit=crop" alt="Artist" class="team-img">
                        <div class="team-name">Sarah Jenkins</div>
                        <div class="team-role">Abstract Specialist</div>
                    </div>
                    <div class="team-member" data-aos="fade-up" data-aos-delay="300">
                        <img src="https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?q=80&w=400&auto=format&fit=crop" alt="Artist" class="team-img">
                        <div class="team-name">James Liu</div>
                        <div class="team-role">Resident Sculptor</div>
                    </div>
                <?php else: ?>
                    <?php foreach ($team_members as $index => $member): ?>
                    <div class="team-member" data-aos="fade-up" data-aos-delay="<?php echo ($index * 100) + 100; ?>">
                        <img src="uploads/team/<?php echo htmlspecialchars($member['image_path']); ?>" alt="<?php echo htmlspecialchars($member['name']); ?>" class="team-img">
                        <div class="team-name"><?php echo htmlspecialchars($member['name']); ?></div>
                        <div class="team-role"><?php echo htmlspecialchars($member['role']); ?></div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

        </div>
    </section>

    <footer>
        <div class="container">
            <div class="footer-grid">
                <div class="footer-about">
                    <a class="footer-logo">
                        <span class="logo-top">THE</span>
                        <span class="logo-main">
                        <span class="logo-red">M</span><span class="logo-text">an</span><span class="logo-red">C</span><span class="logo-text">ave</span>
                        </span>
                        <span class="logo-bottom">GALLERY</span>
                    </a>
                    <p>Where passion meets preservation. Located in Pampanga.</p>
                    <div class="socials">
                        <a href="https://web.facebook.com/profile.php?id=61581718054821&_rdc=1&_rdr#" target="_blank"><i class="fab fa-facebook-f"></i></a>
                        <a href="https://www.instagram.com/the_mancave_gallery_ph?igsh=MW9wczBzcWpka3E3Nw==" target="_blank"><i class="fab fa-instagram"></i></a>
                    </div>
                </div>
                <div class="footer-links">
                    <h4>Explore</h4>
                    <ul>
                        <li><a href="index.php">Home</a></li>
                        <li><a href="collection">Collection</a></li>
                        <li><a href="index.php#artists">Artists</a></li>
                        <li><a href="index.php#services">Services</a></li>
                        <li><a href="index.php#contact-form">Visit</a></li>
                    </ul>
                </div>
                <div class="footer-contact">
                    <h4>Contact</h4>
                    <p><i class="fas fa-envelope"></i> mancave.artgallery@gmail.com</p>
                    <p><i class="fas fa-phone"></i> +63 945 264 0598</p>
                    <p><i class="fas fa-map-marker-alt"></i> San Antonio Road, Purok Dayat, San Antonio, Guagua, Philippines</p>
                </div>
            </div>
            <div class="footer-bottom">
                © 2025 Man Cave Art Gallery. All Rights Reserved.
            </div>
        </div>
    </footer>

    <div class="modal-overlay" id="messageModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-check-circle" style="color: #27ae60;"></i></div>
            <h3 id="msgTitle">Success!</h3>
            <p id="msgBody">Operation successful.</p>
            <button class="btn-friendly" onclick="closeModal('messageModal')">Okay</button>
        </div>
    </div>
    
    <div class="modal-overlay" id="loginModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-user-circle"></i></div>
            <h3>Welcome Back</h3>
            <p>Sign in to continue to your account</p>
            <?php if(isset($_SESSION['error_message']) && isset($_GET['login'])): ?>
                <div class="alert-error" style="text-align:left;"><i class="fas fa-exclamation-circle"></i> <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?></div>
            <?php endif; ?>
            <form action="about.php" method="POST"> 
                <div class="friendly-input-group"><input type="text" name="identifier" required placeholder="Username or Email"><i class="fas fa-user"></i></div>
                <div class="friendly-input-group" style="margin-bottom:10px;"><input type="password" name="password" required placeholder="Password"><i class="fas fa-lock"></i></div>
                <div style="text-align: right; margin-bottom: 20px;"><a href="#" class="forgot-pass-link" id="openForgotBtn">Forgot Password?</a></div>
                <button type="submit" name="login" class="btn-friendly">Sign In</button>
                <div class="modal-footer-link">Don't have an account? <a href="#" id="switchRegister">Sign Up</a></div>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="signupModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-rocket"></i></div>
            <h3>Join The Club</h3>
            <p>Create an account to reserve unique art</p>
            <?php if(isset($_SESSION['error_message']) && isset($_GET['signup'])): ?>
                <div class="alert-error" style="text-align:left;"><i class="fas fa-exclamation-circle"></i> <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?></div>
            <?php endif; ?>
            <form action="about.php" method="POST"> 
                <div class="friendly-input-group"><input type="text" name="username" required placeholder="Username"><i class="fas fa-user"></i></div>
                <div class="friendly-input-group"><input type="email" name="email" required placeholder="Email Address"><i class="fas fa-envelope"></i></div>
                <div class="friendly-input-group"><input type="password" name="password" required placeholder="Password (Min 8 chars)"><i class="fas fa-lock"></i></div>
                <div class="friendly-input-group"><input type="password" name="confirm_password" required placeholder="Confirm Password"><i class="fas fa-check-circle"></i></div>
                <button type="submit" name="sign" class="btn-friendly">Create Account</button>
                <div class="modal-footer-link">Already a member? <a href="#" id="switchLogin">Log In</a></div>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="forgotModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-key"></i></div>
            <h3>Forgot Password</h3>
            <p>Enter your email to receive an OTP code.</p>
            <form id="forgotForm">
                <div class="friendly-input-group"><input type="email" id="resetEmail" name="email" required placeholder="Email Address"><i class="fas fa-envelope"></i></div>
                <button type="submit" class="btn-friendly">Send OTP</button>
                <div class="modal-footer-link">Remembered it? <a href="#" class="switchBackToLogin">Log In</a></div>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="resetOtpModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-shield-alt"></i></div>
            <h3>Verify Code</h3>
            <p>Enter the 6-digit code sent to your email.</p>
            <form id="resetOtpForm">
                <div class="friendly-input-group"><input type="text" id="otpCode" name="otp" required placeholder="123456" maxlength="6" style="letter-spacing:5px; text-align:center; font-weight:700; font-size:1.2rem;"><i class="fas fa-key"></i></div>
                <button type="submit" class="btn-friendly">Verify Code</button>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="newPasswordModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-lock-open"></i></div>
            <h3>New Password</h3>
            <p>Create a secure new password for your account.</p>
            <form id="newPasswordForm">
                <div class="friendly-input-group"><input type="password" id="newPass" name="new_password" required placeholder="New Password"><i class="fas fa-lock"></i></div>
                <div class="friendly-input-group"><input type="password" id="confirmPass" name="confirm_password" required placeholder="Confirm Password"><i class="fas fa-check-circle"></i></div>
                <button type="submit" class="btn-friendly">Reset Password</button>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="verifyAccountModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-check-circle"></i></div>
            <h3>Verify Account</h3>
            <p>Enter the 6-digit code sent to <?php echo htmlspecialchars($_SESSION['otp_email'] ?? 'your email'); ?>.</p>
            <?php if(isset($_SESSION['error_message']) && isset($_SESSION['show_verify_modal'])): ?>
                <div class="alert-error" style="text-align:left;"><i class="fas fa-exclamation-circle"></i> <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?></div>
            <?php endif; ?>
            <form method="POST">
                <div class="friendly-input-group"><input type="text" name="otp" required placeholder="000000" maxlength="6" style="text-align:center; letter-spacing:5px; font-weight:700; font-size:1.2rem;"><i class="fas fa-key"></i></div>
                <button type="submit" name="verify_account" class="btn-friendly">Verify Now</button>
            </form>
        </div>
    </div>

    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
        AOS.init({ duration: 800, offset: 50 });
        
        // --- BURGER MENU TOGGLE ---
        function toggleMobileMenu() {
            const navLinks = document.getElementById('navLinks');
            navLinks.classList.toggle('active');
        }
        
         // --- NAVBAR & HEADER ---
        window.addEventListener('scroll', () => {
            const navbar = document.querySelector('.navbar');
            if(window.scrollY > 50) navbar.classList.add('scrolled');
            else navbar.classList.remove('scrolled');
        });

        // --- MODAL LOGIC (COPIED FROM INDEX.PHP) ---
        const loginModal = document.getElementById('loginModal');
        const signupModal = document.getElementById('signupModal');
        const forgotModal = document.getElementById('forgotModal');
        const resetOtpModal = document.getElementById('resetOtpModal');
        const newPasswordModal = document.getElementById('newPasswordModal');
        const verifyAccountModal = document.getElementById('verifyAccountModal');
        const messageModal = document.getElementById('messageModal'); 
        const closeBtns = document.querySelectorAll('.modal-close');

        function closeModal(id) { 
            if(id) document.getElementById(id).classList.remove('active');
            else document.querySelectorAll('.modal-overlay').forEach(el => el.classList.remove('active'));
        }
        
        closeBtns.forEach(btn => btn.addEventListener('click', () => closeModal()));
        window.addEventListener('click', (e) => { if (e.target.classList.contains('modal-overlay')) closeModal(); });

        document.getElementById('openLoginBtn')?.addEventListener('click', () => { closeModal(); loginModal.classList.add('active'); });
        document.getElementById('openSignupBtn')?.addEventListener('click', () => { closeModal(); signupModal.classList.add('active'); });
        document.getElementById('switchRegister')?.addEventListener('click', (e) => { e.preventDefault(); closeModal(); signupModal.classList.add('active'); });
        document.getElementById('switchLogin')?.addEventListener('click', (e) => { e.preventDefault(); closeModal(); loginModal.classList.add('active'); });
        document.getElementById('openForgotBtn')?.addEventListener('click', (e) => { e.preventDefault(); closeModal(); forgotModal.classList.add('active'); });
        document.querySelectorAll('.switchBackToLogin').forEach(btn => {
            btn.addEventListener('click', (e) => { e.preventDefault(); closeModal(); loginModal.classList.add('active'); });
        });

        // PHP Triggered Modals
        <?php if(isset($_GET['login'])): ?> loginModal.classList.add('active'); <?php endif; ?>
        <?php if(isset($_GET['signup'])): ?> signupModal.classList.add('active'); <?php endif; ?>
        <?php if(isset($_SESSION['show_verify_modal'])): ?> verifyAccountModal.classList.add('active'); <?php unset($_SESSION['show_verify_modal']); ?> <?php endif; ?>

        window.showModalMessage = function(title, body) {
            document.getElementById('msgTitle').innerText = title;
            document.getElementById('msgBody').innerText = body;
            document.getElementById('messageModal').classList.add('active');
        }

        <?php if(isset($_SESSION['success_message'])): ?>
            showModalMessage('Success!', '<?php echo addslashes($_SESSION['success_message']); ?>');
        <?php unset($_SESSION['success_message']); endif; ?>

        // --- FORGOT PASSWORD FLOW (AJAX) ---
        let resetEmail = '';
        document.getElementById('forgotForm').addEventListener('submit', function(e) {
            e.preventDefault();
            resetEmail = document.getElementById('resetEmail').value;
            const btn = this.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
            const formData = new FormData();
            formData.append('ajax_action', 'send_reset_otp');
            formData.append('email', resetEmail);
            fetch('about.php', { method: 'POST', body: formData }).then(r => r.json()).then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') { forgotModal.classList.remove('active'); resetOtpModal.classList.add('active'); } 
                else { alert(data.message); }
            }).catch(() => { btn.disabled = false; btn.innerHTML = originalText; alert('Error sending request.'); });
        });
        document.getElementById('resetOtpForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const otp = document.getElementById('otpCode').value;
            const btn = this.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = 'Verifying...';
            const formData = new FormData();
            formData.append('ajax_action', 'verify_reset_otp');
            formData.append('email', resetEmail);
            formData.append('otp', otp);
            fetch('about.php', { method: 'POST', body: formData }).then(r => r.json()).then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') { resetOtpModal.classList.remove('active'); newPasswordModal.classList.add('active'); } 
                else { alert(data.message); }
            });
        });
        document.getElementById('newPasswordForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const newPass = document.getElementById('newPass').value;
            const confirmPass = document.getElementById('confirmPass').value;
            const otp = document.getElementById('otpCode').value; 
            const btn = this.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = 'Resetting...';
            const formData = new FormData();
            formData.append('ajax_action', 'reset_password');
            formData.append('email', resetEmail);
            formData.append('otp', otp);
            formData.append('new_password', newPass);
            formData.append('confirm_password', confirmPass);
            fetch('about.php', { method: 'POST', body: formData }).then(r => r.json()).then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') { showModalMessage('Password Reset', 'Password reset successful! You can now log in.'); closeModal(); loginModal.classList.add('active'); } 
                else { alert(data.message); }
            });
        });

        // --- NOTIFICATIONS LOGIC ---
        document.addEventListener('DOMContentLoaded', () => {
            const notifBtn = document.getElementById('notifBtn');
            const notifDropdown = document.getElementById('notifDropdown');
            const notifBadge = document.getElementById('notifBadge');
            const notifList = document.getElementById('notifList');
            const markAllReadBtn = document.getElementById('markAllRead');
            const userDropdown = document.querySelector('.user-dropdown');
            const profilePill = document.querySelector('.profile-pill');

            if (profilePill && userDropdown) {
                profilePill.addEventListener('click', (e) => {
                    e.stopPropagation();
                    userDropdown.classList.toggle('active');
                    if (notifDropdown) notifDropdown.classList.remove('active');
                });
                userDropdown.addEventListener('click', (e) => e.stopPropagation());
            }

            if (notifBtn) {
                notifBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    notifDropdown.classList.toggle('active');
                    if (userDropdown) userDropdown.classList.remove('active');
                });

                function fetchNotifications() {
                    fetch('fetch_notifications.php')
                        .then(res => res.json())
                        .then(data => {
                            if (data.status === 'success') {
                                if (data.unread_count > 0) {
                                    notifBadge.innerText = data.unread_count;
                                    notifBadge.style.display = 'block';
                                } else {
                                    notifBadge.style.display = 'none';
                                }

                                notifList.innerHTML = '';
                                if (data.notifications.length === 0) {
                                    notifList.innerHTML = '<li class="no-notif">No new notifications</li>';
                                } else {
                                    data.notifications.forEach(notif => {
                                        const item = document.createElement('li');
                                        item.className = `notif-item ${notif.is_read == 0 ? 'unread' : ''}`;
                                        item.innerHTML = `
                                            <div class="notif-msg">${notif.message}</div>
                                            <div class="notif-time">${notif.created_at}</div>
                                            <button class="btn-notif-close" title="Delete">×</button>
                                        `;
                                        item.addEventListener('click', (e) => {
                                            if (e.target.classList.contains('btn-notif-close')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('mark_as_read.php', { method: 'POST', body: formData })
                                                .then(() => fetchNotifications());
                                        });
                                        item.querySelector('.btn-notif-close').addEventListener('click', (e) => {
                                            e.stopPropagation();
                                            if(confirm('Delete this notification?')) {
                                                const fd = new FormData();
                                                fd.append('id', notif.id);
                                                fetch('delete_notifications.php', { method:'POST', body:fd })
                                                    .then(r=>r.json()).then(d=>{ if(d.status==='success') fetchNotifications(); });
                                            }
                                        });
                                        notifList.appendChild(item);
                                    });
                                }
                            }
                        })
                        .catch(err => console.error('Error:', err));
                }

                if (markAllReadBtn) {
                    markAllReadBtn.addEventListener('click', () => {
                        fetch('mark_all_as_read.php', { method: 'POST' })
                            .then(() => fetchNotifications());
                    });
                }

                fetchNotifications();
                setInterval(fetchNotifications, 30000);
            }

            window.addEventListener('click', () => {
                if (notifDropdown) notifDropdown.classList.remove('active');
                if (userDropdown) userDropdown.classList.remove('active');
            });
            if (notifDropdown) notifDropdown.addEventListener('click', (e) => e.stopPropagation());
        });
    </script>
</body>
</html>