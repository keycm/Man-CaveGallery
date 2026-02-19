<?php
session_start();
include 'config.php';
require_once __DIR__ . '/reset_mailer.php'; 

// =================================================================
// 0. FETCH HERO IMAGES (NEW FEATURE)
// =================================================================
$hero_slides = [];
$res_hero = mysqli_query($conn, "SELECT * FROM hero_slides ORDER BY id DESC");
if ($res_hero && mysqli_num_rows($res_hero) > 0) {
    while ($row = mysqli_fetch_assoc($res_hero)) {
        $hero_slides[] = 'uploads/hero/' . $row['image_path'];
    }
} else {
    // Fallback if no images are uploaded
    $hero_slides = [
        'Grand Opening - Man Cave Gallery/img-21.jpg',
        'Grand Opening - Man Cave Gallery/img-10.jpg',
        'Grand Opening - Man Cave Gallery/img-17.jpg',
        'Grand Opening - Man Cave Gallery/img-12.jpg'
    ];
}

// Calculate Animation Timings Dynamically
$slide_count = count($hero_slides);
$slide_duration = 5; // Seconds per slide
$total_duration = $slide_count * $slide_duration;

// Calculate Keyframe percentages
// Fade In (1s) -> Hold (4s) -> Fade Out (1s)
$fade_in_pct = round((1 / $total_duration) * 100, 2); 
$hold_pct    = round(($slide_duration / $total_duration) * 100, 2); 
$fade_out_pct = round((($slide_duration + 1) / $total_duration) * 100, 2); 

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
            
            // Check if email exists
            $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $res = $stmt->get_result();
            
            if ($res->num_rows > 0) {
                $user = $res->fetch_assoc();
                $otp = random_int(100000, 999999);
                $otp_hash = hash("sha256", $otp); // Hash OTP for security
                $expiry = date("Y-m-d H:i:s", time() + 60 * 15); // 15 mins

                // Update DB
                $update = $conn->prepare("UPDATE users SET reset_token_hash = ?, reset_token_expires_at = ? WHERE id = ?");
                $update->bind_param("ssi", $otp_hash, $expiry, $user['id']);
                
                if ($update->execute()) {
                    // Send Email
                    $mail = require __DIR__ . '/reset_mailer.php';
                    $mail->setFrom("noreply@example.com", "ManCave Gallery");
                    $mail->addAddress($email);
                    $mail->Subject = "Password Reset OTP";
                    $mail->isHTML(true);
                    $mail->Body = "
                        <h3>Password Reset Request</h3>
                        <p>Hi " . htmlspecialchars($user['username']) . ",</p>
                        <p>Your OTP code to reset your password is:</p>
                        <h2 style='background: #eee; padding: 10px; display: inline-block;'>$otp</h2>
                        <p>This code expires in 15 minutes.</p>
                    ";
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
                // Verify OTP again before updating
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

// --- ACCOUNT VERIFICATION LOGIC (OTP) - NEW ---
if (isset($_POST['verify_account'])) {
    $otp_input = trim($_POST['otp']);
    $email = $_SESSION['otp_email'] ?? '';

    if (empty($email)) {
        $_SESSION['error_message'] = "Session expired. Please sign up again.";
    } elseif (empty($otp_input)) {
        $_SESSION['error_message'] = "Please enter the code.";
        $_SESSION['show_verify_modal'] = true; // Keep modal open
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
            header("Location: index.php?login=1");
            exit;
        } else {
            $expiry = strtotime($user['reset_token_expires_at']);
            
            // Force string comparison
            $db_otp = (string)$user['account_activation_hash'];
            $input_otp = (string)$otp_input;

            if (time() > $expiry) {
                $_SESSION['error_message'] = "Code expired. Please register again.";
            } elseif ($db_otp !== $input_otp) {
                $_SESSION['error_message'] = "Incorrect code. Try again.";
                $_SESSION['show_verify_modal'] = true; // Keep modal open
            } else {
                // --- SUCCESS: ACTIVATE ---
                $upd = $conn->prepare("UPDATE users SET account_activation_hash = NULL, reset_token_expires_at = NULL WHERE id = ?");
                $upd->bind_param("i", $user['id']);
                if ($upd->execute()) {
                    // UPDATED SUCCESS MESSAGE
                    $_SESSION['success_message'] = "You are successfully registered";
                    unset($_SESSION['otp_email']);
                    unset($_SESSION['show_verify_modal']);
                    // Redirect to index (Alert will show via session check)
                    header("Location: index.php");
                    exit;
                } else {
                    $_SESSION['error_message'] = "Database error.";
                }
            }
        }
    }
    header("Location: index.php");
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
            $_SESSION['show_verify_modal'] = true; // Open verify modal
            header("Location: index.php");
            exit();
        }
        if (password_verify($password, $row['password'])) {
            $_SESSION['username'] = $row['username'];
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['role'] = $row['role'];
            header("Location: " . ($row['role'] == 'admin' ? 'admin.php' : 'index.php'));
            exit();
        } else {
            $_SESSION['error_message'] = "Invalid password!";
        }
    } else {
        $_SESSION['error_message'] = "User not found!";
    }
    if(isset($_SESSION['error_message'])) {
        header("Location: index.php?login=1");
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
                        $_SESSION['show_verify_modal'] = true; // Use this flag instead of redirect
                        header("Location: index.php"); // Redirect back to index
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
        header("Location: index.php?signup=1");
        exit();
    }
}

// =================================================================
// 2. FETCH DATA (Artworks, Artists, etc)
// =================================================================

$loggedIn = isset($_SESSION['username']);

// 1. Fetch Artworks (Latest Arrivals - SCROLL ALL)
$seven_days_ago = date('Y-m-d', strtotime('-7 days'));
$artworks = [];

// UPDATED QUERY: Removed LIMIT 3, Changed ORDER BY to id DESC (Latest)
$sql_art = "SELECT a.*, 
            (
                SELECT status 
                FROM bookings b 
                WHERE (b.artwork_id = a.id OR b.service = a.title) 
                AND b.status IN ('approved', 'completed') 
                ORDER BY b.id DESC LIMIT 1
            ) as active_booking_status,
            (SELECT COUNT(*) FROM favorites f WHERE f.artwork_id = a.id) as fav_count
            FROM artworks a
            WHERE (
                SELECT COUNT(*) 
                FROM bookings b2
                WHERE (b2.artwork_id = a.id OR b2.service = a.title)
                AND b2.status = 'completed' 
                AND b2.preferred_date < '$seven_days_ago'
            ) = 0
            ORDER BY id DESC"; // Fetching all latest

$res_art = mysqli_query($conn, $sql_art);
if ($res_art) { while ($row = mysqli_fetch_assoc($res_art)) { $artworks[] = $row; } }

// 2. Fetch Single Artist (Meet The Artist - FIXED)
$single_artist = []; // Default empty
$sql_artist = "SELECT * FROM artists LIMIT 1"; // Fetch only the first artist
$res_artist = mysqli_query($conn, $sql_artist);
if ($res_artist && mysqli_num_rows($res_artist) > 0) { 
    $single_artist = mysqli_fetch_assoc($res_artist); 
}

// 3. Fetch Services (Gallery Services - LIMIT 3)
$services_list = [];
$sql_services = "SELECT * FROM services ORDER BY id ASC LIMIT 3";
if ($res_services = mysqli_query($conn, $sql_services)) { 
    while ($row = mysqli_fetch_assoc($res_services)) { $services_list[] = $row; } 
}

// 4. Fetch Events (Upcoming Events - LIMIT 2)
$events_list = [];
$sql_events = "SELECT * FROM events ORDER BY event_date ASC LIMIT 2";
if ($res_events = mysqli_query($conn, $sql_events)) { 
    while ($row = mysqli_fetch_assoc($res_events)) { $events_list[] = $row; } 
}

// 5. Fetch Client Stories (LIMIT 3)
$reviews_list = [];
$sql_review = "SELECT r.*, u.username, s.name as service_name 
               FROM ratings r 
               JOIN users u ON r.user_id = u.id 
               LEFT JOIN services s ON r.service_id = s.id
               WHERE r.rating >= 4 
               ORDER BY RAND() LIMIT 3";
if ($res_review = mysqli_query($conn, $sql_review)) {
    while ($row = mysqli_fetch_assoc($res_review)) {
        $reviews_list[] = $row;
    }
}

// 6. Fetch News Updates (NEW CONNECTION TO manage_news.php)
$news_list = [];
$sql_news = "SELECT * FROM announcements WHERE is_active = 1 ORDER BY created_at DESC LIMIT 3";
if ($res_news = mysqli_query($conn, $sql_news)) {
    while ($row = mysqli_fetch_assoc($res_news)) {
        $news_list[] = $row;
    }
}

// 7. Fetch User Data for Header
$user_favorites = [];
$user_profile_pic = ""; 
if ($loggedIn && isset($_SESSION['user_id'])) {
    $uid = $_SESSION['user_id'];
    $fav_sql = "SELECT artwork_id FROM favorites WHERE user_id = $uid";
    if ($fav_res = mysqli_query($conn, $fav_sql)) {
        while($r = mysqli_fetch_assoc($fav_res)){ $user_favorites[] = $r['artwork_id']; }
    }
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The ManCave Art Gallery</title>
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@300;400;600;700;800&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="home.css">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    
    <style>
    
            /* ========================================== */
        /* === DYNAMIC SLIDER ANIMATIONS === */
        /* ========================================== */
        <?php if ($slide_count > 0): ?>
            @keyframes dynamicSlideShow {
                0% { opacity: 0; transform: scale(1.05); }
                <?php echo $fade_in_pct; ?>% { opacity: 1; }
                <?php echo $hold_pct; ?>% { opacity: 1; }
                <?php echo $fade_out_pct; ?>% { opacity: 0; transform: scale(1); }
                100% { opacity: 0; }
            }
            .slide {
                animation: dynamicSlideShow <?php echo $total_duration; ?>s infinite;
            }
            <?php foreach($hero_slides as $index => $url): ?>
            .slide:nth-child(<?php echo $index + 1; ?>) {
                animation-delay: <?php echo $index * $slide_duration; ?>s;
            }
            <?php endforeach; ?>
        <?php endif; ?>
        
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
                <li><a href="#home">Home</a></li>
                <li><a href="#gallery">Collection</a></li>
                <li><a href="#artists">Artists</a></li>
                <li><a href="#services">Services</a></li>
                <li><a href="#news">News</a></li>
                <li><a href="#contact-form">Visit</a></li>
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

    <header id="home" class="hero">
        <div class="hero-slider">
            <?php foreach($hero_slides as $index => $slide_url): ?>
                <div class="slide" style="background-image: url('<?php echo htmlspecialchars($slide_url); ?>');"></div>
            <?php endforeach; ?>
        </div>
        <div class="hero-overlay"></div>
        <div class="container hero-content text-center" data-aos="fade-up">
            <p class="hero-subtitle">Welcome to the Sanctuary</p>
            <h1>Art That Tells Your Story</h1>
            <p class="hero-description">Explore a curated collection of contemporary masterpieces designed to inspire, provoke, and transform your space.</p>
            <div class="hero-btns">
                <a href="#gallery" class="btn-primary">Browse Collection</a>
                <a href="#about" class="btn-outline">Our Story</a>
            </div>
            <div class="scroll-indicator"><span class="line"></span><span class="line"></span><span class="line"></span></div>
        </div>
    </header>

    <section id="about" class="section-padding bg-white">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-6" data-aos="fade-right">
                    <div class="image-stack">
                        <img src="Grand Opening - Man Cave Gallery/img-17.jpg" class="img-back" alt="Gallery Art">
                        <img src="Grand Opening - Man Cave Gallery/img-21.jpg" class="img-front" alt="Gallery Interior">
                    </div>
                </div>
                <div class="col-6 content-padding" data-aos="fade-left">
                    <h4 class="section-tag">About Us</h4>
                    <h2 class="section-title">A Space for Connection</h2>
                    <p class="section-text">
                        ManCave Gallery isn't just about hanging pictures on a wall. It's about the conversation that happens in front of them. 
                        We have been bridging the gap between visionary artists and passionate collectors.
                    </p>
                    <ul class="feature-list">
                        <li><i class="fas fa-check"></i> Curated by Experts</li>
                        <li><i class="fas fa-check"></i> Authenticity Guaranteed</li>
                        <li><i class="fas fa-check"></i> Exclusive Private Viewings</li>
                    </ul>
                    <a href="about" class="link-arrow">Learn More <i class="fas fa-arrow-right"></i></a> </div>
            </div>
        </div>
    </section>

    <section id="artists" class="section-padding bg-light">
        <div class="container">
            <div class="text-center mb-5">
                <h4 class="section-tag">The Creator</h4>
                <h2 class="section-title">Meet The Artist</h2>
            </div>
            <div class="row align-items-center">
                <div class="col-6" data-aos="fade-right">
                    <div style="box-shadow: 0 15px 40px rgba(0,0,0,0.15); border-radius: 12px; overflow: hidden;">
                        <?php 
                            // Check if image exists, otherwise use fallback
                            $artistImg = !empty($single_artist['image_path']) ? 'uploads/' . $single_artist['image_path'] : 'image_a6bbe0.jpg'; 
                        ?>
                        <img src="<?php echo htmlspecialchars($artistImg); ?>" alt="Artist Profile" style="width: 100%; display: block;">
                    </div>
                </div>
                <div class="col-6 content-padding" data-aos="fade-left">
                    <h3 style="font-size: 2.5rem; font-family: var(--font-head); color: var(--primary); margin-bottom: 10px;">
                        <?php echo !empty($single_artist['name']) ? htmlspecialchars($single_artist['name']) : 'The Artist'; ?>
                    </h3>
                    <p style="color: var(--accent-orange); font-weight: 700; margin-bottom: 20px;">
                        <?php echo !empty($single_artist['style']) ? htmlspecialchars($single_artist['style']) : 'Visionary Creator'; ?>
                    </p>
                    <p class="section-text">
                        <?php echo !empty($single_artist['bio']) ? nl2br(htmlspecialchars($single_artist['bio'])) : 'Discover the story behind the art...'; ?>
                    </p>
                    
                    <?php if(!empty($single_artist['quote'])): ?>
                        <blockquote style="font-style: italic; color: #666; border-left: 3px solid var(--accent-orange); padding-left: 15px; margin: 20px 0;">
                            "<?php echo htmlspecialchars($single_artist['quote']); ?>"
                        </blockquote>
                    <?php endif; ?>

                    <a href="artist_profile.php" class="btn-primary" style="margin-top: 20px;">View Portfolio</a>
                </div>
            </div>
        </div>
    </section>

    <section id="gallery" class="section-padding">
        <div class="container">
            <div class="flex-header">
                <div>
                    <h4 class="section-tag">Inventory</h4>
                    <h2 class="section-title">Latest Arrivals</h2>
                </div>
                <a href="collection" class="btn-outline-dark">View All Works</a> 
            </div>

            <div class="marquee-wrapper" id="marqueeWrapper">
                <div class="marquee-track" id="marqueeTrack">
                    <?php if (empty($artworks)): ?>
                        <div class="col-12 text-center" style="width:100%;">
                            <p>No artworks found.</p>
                        </div>
                    <?php else: ?>
                        <?php 
                        // DOUBLE LOOP FOR SEAMLESS SCROLL EFFECT
                        for ($i = 0; $i < 2; $i++): 
                            foreach ($artworks as $art): 
                                $isSold = ($art['status'] === 'Sold' || $art['active_booking_status'] === 'completed');
                                $isReserved = ($art['status'] === 'Reserved' || $art['active_booking_status'] === 'approved');
                                $isAvailable = ($art['status'] === 'Available' && !$isSold && !$isReserved);
                                
                                if ($isSold) {
                                    $statusDisplay = 'Sold';
                                    $statusClass = 'sold';
                                } elseif ($isReserved) {
                                    $statusDisplay = 'Reserved';
                                    $statusClass = 'reserved';
                                } else {
                                    $statusDisplay = 'Available';
                                    $statusClass = 'available';
                                }

                                $imgSrc = !empty($art['image_path']) ? 'uploads/'.$art['image_path'] : 'https://images.unsplash.com/photo-1578301978693-85fa9c0320b9?q=80&w=600&auto=format&fit=crop';
                                $isFav = in_array($art['id'], $user_favorites);
                                $heartIcon = $isFav ? 'fas fa-heart' : 'far fa-heart';
                                $favCount = $art['fav_count'] ?? 0;
                        ?>
                        <div class="art-card-new">
                            <div class="art-img-wrapper-new">
                                <?php if(!$isAvailable || $isSold): ?>
                                    <span class="badge-new <?php echo $statusClass; ?>"><?php echo $statusDisplay; ?></span>
                                <?php endif; ?>
                                <a href="artwork_details?id=<?php echo $art['id']; ?>" class="art-link-wrapper"> 
                                    <img src="<?php echo htmlspecialchars($imgSrc); ?>" alt="<?php echo htmlspecialchars($art['title']); ?>" draggable="false">
                                    <div class="explore-overlay">
                                        <div class="explore-icon">
                                            <i class="fas fa-eye"></i>
                                        </div>
                                        <p class="explore-text">CLICK TO VIEW</p>
                                    </div>
                                </a>
                            </div>
                            
                            <div class="art-content-new">
                                <div class="art-title-new"><?php echo htmlspecialchars($art['title']); ?></div>
                                <div class="art-meta-new">
                                    <span class="artist-name-new"><?php echo htmlspecialchars($art['artist']); ?></span>
                                    <span class="art-year-new">2025</span>
                                </div>
                                
                                <div class="art-footer-new">
                                    <span class="price-new">Php <?php echo number_format($art['price']); ?></span>
                                    <div class="action-btns-new">
                                        <button class="btn-circle btn-heart <?php echo $isFav ? 'active' : ''; ?>" 
                                                onclick="toggleFavorite(this, <?php echo $art['id']; ?>)" 
                                                title="Toggle Favorite"
                                                style="width:auto; padding:0 12px; border-radius:50px; display:flex; align-items:center; gap:5px;">
                                            <i class="<?php echo $heartIcon; ?>"></i>
                                            <span class="fav-count" style="font-size:0.8rem; font-weight:700;"><?php echo $favCount; ?></span>
                                        </button>
                                        
                                        <?php if($isSold || $isReserved): ?>
                                            <button class="btn-circle" 
                                                    onclick="openCopyModal('<?php echo addslashes($art['title']); ?>')" 
                                                    title="Request a Copy">
                                                <i class="fas fa-clone"></i>
                                            </button>
                                        <?php elseif($isAvailable): ?>
                                            <button class="btn-circle btn-cart" 
                                                    onclick="animateCart(this); openReserveModal(<?php echo $art['id']; ?>, '<?php echo addslashes($art['title']); ?>')" 
                                                    title="Reserve Artwork">
                                                <i class="fas fa-shopping-cart"></i>
                                            </button>
                                        <?php else: ?>
                                            <button class="btn-circle disabled" title="Unavailable">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; endfor; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </section>

    <section id="services" class="section-padding bg-dark text-white">
        <div class="container">
            <div class="text-center mb-5">
                <h4 class="section-tag text-accent">What We Offer</h4>
                <h2 class="section-title text-white">Gallery Services</h2>
            </div>
            <div class="grid-3">
                <?php if(empty($services_list)): ?>
                    <p class="text-center" style="grid-column:1/-1;">No services added yet.</p>
                <?php else: foreach($services_list as $srv): 
                    $icons = ['fa-gem', 'fa-crop-alt', 'fa-truck-loading'];
                    $icon = $icons[array_rand($icons)]; 
                ?>
                    <div class="service-item" data-aos="zoom-in">
                        <i class="fas <?php echo $icon; ?>"></i>
                        <h3><?php echo htmlspecialchars($srv['name']); ?></h3>
                        <p><?php echo htmlspecialchars($srv['description']); ?></p>
                        <small style="color:var(--accent); font-weight:700;">Starting at ₱<?php echo number_format($srv['price']); ?></small>
                    </div>
                <?php endforeach; endif; ?>
            </div>
        </div>
    </section>

    <section id="news" class="section-padding bg-white">
        <div class="container">
            <div class="text-center mb-5">
                <h4 class="section-tag">Updates</h4>
                <h2 class="section-title">Latest News</h2>
            </div>
            <div class="grid-3">
                <?php if(empty($news_list)): ?>
                    <p class="text-center" style="grid-column: 1/-1;">No updates available.</p>
                <?php else: foreach($news_list as $news): ?>
                    <div class="news-card-home" data-aos="fade-up">
                        <?php 
                            // Only display image container if an image path exists
                            if(!empty($news['image_path'])): 
                        ?>
                            <div class="news-img-container">
                                <img src="uploads/<?php echo htmlspecialchars($news['image_path']); ?>" alt="<?php echo htmlspecialchars($news['title']); ?>">
                            </div>
                        <?php endif; ?>
                        
                        <div class="news-content-wrapper">
                            <span class="news-date"><i class="far fa-calendar-alt"></i> <?php echo date('M d, Y', strtotime($news['created_at'])); ?></span>
                            <div class="news-title"><?php echo htmlspecialchars($news['title']); ?></div>
                            <div class="news-preview">
                                <?php 
                                    $plain_content = strip_tags($news['content']);
                                    echo (strlen($plain_content) > 100) ? substr($plain_content, 0, 100) . '...' : $plain_content; 
                                ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; endif; ?>
            </div>
        </div>
    </section>

    <section id="events" class="section-padding bg-light">
        <div class="container">
            <div class="events-wrapper">
                <div class="events-content" data-aos="fade-right">
                    <h4 class="section-tag">Community</h4>
                    <h2 class="section-title">Upcoming Events</h2>
                    <p class="section-text">Join us for artist talks, exhibition openings, and workshops. Experience art in a social setting.</p>
                    <div class="event-list">
                        <?php if(empty($events_list)): ?>
                            <p>No upcoming events.</p>
                        <?php else: foreach($events_list as $evt): 
                            $date = strtotime($evt['event_date']);
                        ?>
                            <div class="event-card-row">
                                <div class="date-box">
                                    <span class="day"><?php echo date('d', $date); ?></span>
                                    <span class="month"><?php echo date('M', $date); ?></span>
                                </div>
                                <div class="event-info">
                                    <h4><?php echo htmlspecialchars($evt['title']); ?></h4>
                                    <p><i class="far fa-clock"></i> <?php echo htmlspecialchars($evt['event_time']); ?></p>
                                    <span class="location"><?php echo htmlspecialchars($evt['location']); ?></span>
                                </div>
                            </div>
                        <?php endforeach; endif; ?>
                    </div>
                </div>
                <div class="events-image" data-aos="fade-left">
                    <img src="img-21.jpg" alt="Art Event Crowd">
                </div>
            </div>
        </div>
    </section>

    <section class="section-padding">
        <div class="container text-center">
            <h4 class="section-tag">Testimonials</h4>
            <h2 class="section-title mb-5">Client Stories</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; width: 100%;">
            <?php if(empty($reviews_list)): ?>
                <div class="testimonial-box" style="grid-column: 1/-1;">
                    <div class="quote-icon"><i class="fas fa-quote-left"></i></div>
                    <p class="testimonial-text">"The team at ManCave helped me find the perfect centerpiece for my office. Their knowledge and service are unmatched."</p>
                    <div class="testimonial-author">
                        <img src="https://randomuser.me/api/portraits/men/46.jpg" alt="Client">
                        <div>
                            <h5>James Anderson</h5>
                            <span>Collector</span>
                        </div>
                    </div>
                </div>
            <?php else: foreach($reviews_list as $latest_review): ?>
                <div class="testimonial-box">
                    <div class="quote-icon"><i class="fas fa-quote-left"></i></div>
                    <p class="testimonial-text">"<?php echo htmlspecialchars($latest_review['review']); ?>"</p>
                    <div class="testimonial-author">
                        <img src="https://ui-avatars.com/api/?name=<?php echo urlencode($latest_review['username']); ?>&background=cd853f&color=fff" alt="Client">
                        <div>
                            <h5><?php echo htmlspecialchars($latest_review['username']); ?></h5>
                            <span>Verified Client</span>
                        </div>
                    </div>
                </div>
            <?php endforeach; endif; ?>
            </div>
        </div>
    </section>

    <section id="contact-form" class="section-padding bg-light">
        <div class="container">
            <div class="text-center mb-5">
                <h4 class="section-tag">Get In Touch</h4>
                <h2 class="section-title">Send Us an Inquiry</h2>
            </div>
            <div class="row" style="align-items: stretch;">
                <div class="col-6">
                    <div style="background: var(--white); padding: 40px; border-radius: var(--radius); box-shadow: var(--shadow-soft); height: 100%;">
                        <form id="inquiryForm" action="inquire" method="POST"> <div class="form-group">
                                <label>Email Address</label>
                                <input type="email" name="email" required placeholder="name@example.com">
                            </div>
                            <div class="form-group">
                                <label>Mobile Number</label>
                                <input type="number" name="mobile" required placeholder="09..." maxlength="11">
                            </div>
                            <div class="form-group">
                                <label>Message</label>
                                <textarea name="message" id="contactMessage" rows="5" required placeholder="Tell us about your needs..."></textarea>
                            </div>
                            <button type="submit" class="btn-full" style="margin-top: 20px;">Send Message</button>
                        </form>
                    </div>
                </div>
                <div class="col-6">
                    <div style="height: 100%; min-height: 450px; width: 100%; border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow-soft);">
                        <iframe 
                            src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3854.4242495197054!2d120.60586927493148!3d14.969136585562088!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x33965fd81593ac7b%3A0x548fb1cae8b5e942!2sThe%20ManCave%20Gallery!5e0!3m2!1sen!2sph!4v1764527302397!5m2!1sen!2sph" 
                            width="100%" 
                            height="100%" 
                            style="border:0;" 
                            allowfullscreen="" 
                            loading="lazy" 
                            referrerpolicy="no-referrer-when-downgrade">
                        </iframe>
                    </div>
                </div>
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
                        <li><a href="#gallery">Collection</a></li>
                        <li><a href="#artists">Artists</a></li>
                        <li><a href="#services">Services</a></li>
                        <li><a href="#contact-form">Visit</a></li>
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

    <div class="modal-overlay" id="inquirySuccessModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-paper-plane" style="color: #3b82f6;"></i></div>
            <h3>Inquiry Sent</h3>
            <p>Successfully inquiry please wait for the admin to confirm your inquiry.</p>
            <button class="btn-friendly" onclick="closeModal('inquirySuccessModal')">Okay</button>
        </div>
    </div>

    <div class="modal-overlay" id="loginModal">
        <div class="modal-card small">
            <button class="modal-close">×</button>
            <div class="modal-header-icon"><i class="fas fa-user-circle"></i></div>
            <h3>Welcome Back</h3>
            <p>Sign in to continue to your account</p>
            <?php if(isset($_SESSION['error_message']) && isset($_GET['login'])): ?>
                <div class="alert-error" style="text-align:left;">
                    <i class="fas fa-exclamation-circle"></i> 
                    <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?>
                </div>
            <?php endif; ?>
            <form action="./" method="POST"> 
                <div class="friendly-input-group">
                    <input type="text" name="identifier" required placeholder="Username or Email">
                    <i class="fas fa-user"></i>
                </div>
                <div class="friendly-input-group" style="margin-bottom:10px;">
                    <input type="password" name="password" required placeholder="Password">
                    <i class="fas fa-lock"></i>
                </div>
                <div style="text-align: right; margin-bottom: 20px;">
                    <a href="#" class="forgot-pass-link" id="openForgotBtn">Forgot Password?</a>
                </div>
                <button type="submit" name="login" class="btn-friendly">Sign In</button>
                <div class="modal-footer-link">
                    Don't have an account? <a href="#" id="switchRegister">Sign Up</a>
                </div>
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
                <div class="alert-error" style="text-align:left;">
                    <i class="fas fa-exclamation-circle"></i> 
                    <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?>
                </div>
            <?php endif; ?>
            <form action="./" method="POST"> 
                <div class="friendly-input-group">
                    <input type="text" name="username" required placeholder="Username">
                    <i class="fas fa-user"></i>
                </div>
                <div class="friendly-input-group">
                    <input type="email" name="email" required placeholder="Email Address">
                    <i class="fas fa-envelope"></i>
                </div>
                <div class="friendly-input-group">
                    <input type="password" name="password" required placeholder="Password (Min 8 chars)">
                    <i class="fas fa-lock"></i>
                </div>
                <div class="friendly-input-group">
                    <input type="password" name="confirm_password" required placeholder="Confirm Password">
                    <i class="fas fa-check-circle"></i>
                </div>
                <button type="submit" name="sign" class="btn-friendly">Create Account</button>
                <div class="modal-footer-link">
                    Already a member? <a href="#" id="switchLogin">Log In</a>
                </div>
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
                <div class="friendly-input-group">
                    <input type="email" id="resetEmail" name="email" required placeholder="Email Address">
                    <i class="fas fa-envelope"></i>
                </div>
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
                <div class="friendly-input-group">
                    <input type="text" id="otpCode" name="otp" required placeholder="123456" maxlength="6" style="letter-spacing:5px; text-align:center; font-weight:700; font-size:1.2rem;">
                    <i class="fas fa-key"></i>
                </div>
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
                <div class="friendly-input-group">
                    <input type="password" id="newPass" name="new_password" required placeholder="New Password">
                    <i class="fas fa-lock"></i>
                </div>
                <div class="friendly-input-group">
                    <input type="password" id="confirmPass" name="confirm_password" required placeholder="Confirm Password">
                    <i class="fas fa-check"></i>
                </div>
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
                <div class="alert-error" style="text-align:left;">
                    <i class="fas fa-exclamation-circle"></i> 
                    <?php echo $_SESSION['error_message']; unset($_SESSION['error_message']); ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <div class="friendly-input-group">
                    <input type="text" name="otp" required placeholder="000000" maxlength="6" style="text-align:center; letter-spacing:5px; font-weight:700; font-size:1.2rem;">
                    <i class="fas fa-key"></i>
                </div>
                <button type="submit" name="verify_account" class="btn-friendly">Verify Now</button>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="reserveModal">
        <div class="modal-card">
            <button class="modal-close">×</button>
            <h3 style="margin-bottom:5px;">Secure Reservation</h3>
            <p style="color:#666; margin-bottom:20px; font-size:0.9rem;">Complete your details to secure this piece.</p>
            
            <form action="submit_booking.php" method="POST" enctype="multipart/form-data"> 
                <input type="hidden" id="res_art_id" name="artwork_id">
                <div class="form-group">
                    <label>Selected Artwork</label>
                    <input type="text" id="res_art_title" name="service" readonly style="background:#f9f9f9; color:#555; border-color:#eee;">
                </div>
                <div class="form-group">
                    <label>Preferred Viewing Date</label>
                    <input type="date" name="preferred_date" required min="<?php echo date('Y-m-d'); ?>">
                </div>
                <div style="background:#fdfdfd; border:1px solid #eee; padding:15px; border-radius:8px; margin-bottom:20px;">
                    <h4 style="font-size:0.9rem; color:var(--primary); margin-bottom:15px; border-bottom:1px solid #eee; padding-bottom:5px;">Security Verification</h4>
                    <div class="form-group">
                        <label>Full Legal Name</label>
                        <input type="text" name="full_name" required placeholder="e.g. Juan dela Cruz">
                    </div>
                    <div class="form-group">
                        <label>Contact Number</label>
                        <input type="tel" name="phone_number" required placeholder="09123456789" pattern="[0-9]{11}">
                    </div>
                    <div class="form-group">
                        <label>Valid ID (Government Issued)</label>
                        <input type="file" name="valid_id" accept="image/*" required style="width:100%; padding:10px; border:1px solid #ddd; border-radius:4px;">
                    </div>
                    <p style="font-size:0.75rem; color:#888; margin-top:10px;">
                        <i class="fas fa-shield-alt"></i> Identity verification will be required upon viewing.
                    </p>
                </div>
                <div class="form-group">
                    <label>Special Requests</label>
                    <textarea name="special_requests" rows="2" placeholder="Any specific requirements?"></textarea>
                </div>
                <button type="submit" name="submit_reservation" class="btn-full">Confirm Reservation</button>
            </form>
        </div>
    </div>

    <div class="modal-overlay" id="copyModal">
        <div class="modal-card">
            <button class="modal-close">×</button>
            <h3 style="margin-bottom:5px;">Request a Inquiry</h3>
            <p style="color:#666; margin-bottom:20px; font-size:0.9rem;">This piece is sold, but you can request a commission.</p>
            <form id="commissionForm"> 
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" name="email" required placeholder="Your email">
                </div>
                <div class="form-group">
                    <label>Mobile Number</label>
                    <input type="number" name="mobile" required placeholder="09..." maxlength="11">
                </div>
                <div class="form-group">
                    <label>Message</label>
                    <textarea name="message" id="copyMessage" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn-full">Send Request</button>
            </form>
        </div>
    </div>

    <?php if ($rate_booking): ?>
    <div class="modal-overlay" id="ratingModal">
        <div class="modal-card small">
            <div class="modal-header-icon"><i class="fas fa-star" style="color: #f39c12;"></i></div>
            <h3>Rate Your Experience</h3>
            <p>How was your reservation for "<?php echo htmlspecialchars($rate_booking['service']); ?>"?</p>
            
            <form method="POST">
                <input type="hidden" name="booking_id" value="<?php echo $rate_booking['id']; ?>">
                
                <div class="star-rating">
                    <input type="radio" id="star5" name="rating" value="5" required/><label for="star5" title="Excellent">★</label>
                    <input type="radio" id="star4" name="rating" value="4"/><label for="star4" title="Good">★</label>
                    <input type="radio" id="star3" name="rating" value="3"/><label for="star3" title="Average">★</label>
                    <input type="radio" id="star2" name="rating" value="2"/><label for="star2" title="Poor">★</label>
                    <input type="radio" id="star1" name="rating" value="1"/><label for="star1" title="Very Poor">★</label>
                </div>

                <div class="form-group">
                    <textarea name="review" class="form-control" rows="3" placeholder="Write a short review..." style="width:100%; padding:10px; border-radius:8px; border:1px solid #ddd;"></textarea>
                </div>

                <button type="submit" name="submit_rating" class="btn-friendly">Submit Feedback</button>
                <div class="modal-footer-link">
                    <a href="#" onclick="document.getElementById('ratingModal').classList.remove('active'); return false;" style="color:#999; font-weight:normal;">Maybe Later</a>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>
    
    <script>const isLoggedIn = <?php echo $loggedIn ? 'true' : 'false'; ?>;</script>

    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
        AOS.init({ duration: 800, offset: 50 });

        // --- BURGER MENU TOGGLE ---
        function toggleMobileMenu() {
            const navLinks = document.getElementById('navLinks');
            navLinks.classList.toggle('active');
        }

        // --- GLOBAL VARIABLES & MODALS ---
        const loginModal = document.getElementById('loginModal');
        const signupModal = document.getElementById('signupModal');
        const forgotModal = document.getElementById('forgotModal');
        const resetOtpModal = document.getElementById('resetOtpModal');
        const newPasswordModal = document.getElementById('newPasswordModal');
        const verifyAccountModal = document.getElementById('verifyAccountModal');
        const reserveModal = document.getElementById('reserveModal');
        const copyModal = document.getElementById('copyModal');
        const ratingModal = document.getElementById('ratingModal');
        const messageModal = document.getElementById('messageModal'); 
        const inquirySuccessModal = document.getElementById('inquirySuccessModal'); // NEW MODAL
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

        // Forgot Password Logic
        document.getElementById('openForgotBtn')?.addEventListener('click', (e) => { e.preventDefault(); closeModal(); forgotModal.classList.add('active'); });
        document.querySelectorAll('.switchBackToLogin').forEach(btn => {
            btn.addEventListener('click', (e) => { e.preventDefault(); closeModal(); loginModal.classList.add('active'); });
        });

        // PHP Triggered Modals
        <?php if(isset($_GET['login'])): ?> loginModal.classList.add('active'); <?php endif; ?>
        <?php if(isset($_GET['signup'])): ?> signupModal.classList.add('active'); <?php endif; ?>
        
        // AUTO OPEN VERIFY MODAL IF SESSION SET
        <?php if(isset($_SESSION['show_verify_modal'])): ?>
            verifyAccountModal.classList.add('active');
            <?php unset($_SESSION['show_verify_modal']); ?>
        <?php endif; ?>

        // AUTO OPEN RATING MODAL
        <?php if ($rate_booking): ?>
            setTimeout(() => { ratingModal.classList.add('active'); }, 1500);
        <?php endif; ?>

        // --- HELPER: SHOW MODAL MESSAGE ---
        window.showModalMessage = function(title, body) {
            document.getElementById('msgTitle').innerText = title;
            document.getElementById('msgBody').innerText = body;
            document.getElementById('messageModal').classList.add('active');
        }

        // --- CHECK SESSION FOR SUCCESS MESSAGE (From OTP Verify) ---
        <?php if(isset($_SESSION['success_message'])): ?>
            showModalMessage('Success!', '<?php echo addslashes($_SESSION['success_message']); ?>');
        <?php unset($_SESSION['success_message']); endif; ?>


        // --- FORGOT PASSWORD FLOW (AJAX) ---
        let resetEmail = '';

        // Step 1: Send OTP
        document.getElementById('forgotForm').addEventListener('submit', function(e) {
            e.preventDefault();
            resetEmail = document.getElementById('resetEmail').value;
            const btn = this.querySelector('button');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

            const formData = new FormData();
            formData.append('ajax_action', 'send_reset_otp');
            formData.append('email', resetEmail);

            fetch('./', { method: 'POST', body: formData }) 
            .then(r => r.json())
            .then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') {
                    forgotModal.classList.remove('active');
                    resetOtpModal.classList.add('active');
                } else {
                    alert(data.message);
                }
            }).catch(() => { btn.disabled = false; btn.innerHTML = originalText; alert('Error sending request.'); });
        });

        // Step 2: Verify OTP
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

            fetch('./', { method: 'POST', body: formData }) 
            .then(r => r.json())
            .then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') {
                    resetOtpModal.classList.remove('active');
                    newPasswordModal.classList.add('active');
                } else {
                    alert(data.message);
                }
            });
        });

        // Step 3: Reset Password
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

            fetch('./', { method: 'POST', body: formData }) 
            .then(r => r.json())
            .then(data => {
                btn.disabled = false; btn.innerHTML = originalText;
                if(data.status === 'success') {
                    showModalMessage('Password Reset', 'Password reset successful! You can now log in.');
                    closeModal();
                    loginModal.classList.add('active');
                } else {
                    alert(data.message);
                }
            });
        });

        // --- RESERVATION ---
        window.openReserveModal = function(id, title) {
            if(!isLoggedIn) { loginModal.classList.add('active'); return; }
            document.getElementById('res_art_id').value = id;
            document.getElementById('res_art_title').value = title;
            reserveModal.classList.add('active');
        }

        // --- REQUEST COPY ---
        window.openCopyModal = function(title) {
            document.getElementById('copyMessage').value = "Hello, I am interested in requesting a copy or similar commission of the artwork: \"" + title + "\". Please contact me with details.";
            copyModal.classList.add('active');
        }

        // --- INTERACTION: FAVORITES (AJAX) ---
        window.toggleFavorite = function(btn, id) {
            if(!isLoggedIn) { loginModal.classList.add('active'); return; }
            
            const icon = btn.querySelector('i');
            const countSpan = btn.querySelector('.fav-count');
            let count = parseInt(countSpan.innerText) || 0; // Get current count
            
            const isLiked = btn.classList.contains('active');
            const action = isLiked ? 'remove_id' : 'add_id';

            btn.classList.add('animating');
            
            if(isLiked) {
                // Unlike
                btn.classList.remove('active');
                icon.classList.remove('fas'); icon.classList.add('far');
                count = Math.max(0, count - 1); // Decrement
            } else {
                // Like
                btn.classList.add('active');
                icon.classList.remove('far'); icon.classList.add('fas');
                count++; // Increment
            }
            
            countSpan.innerText = count; // Update UI

            // Send Request
            const formData = new FormData();
            formData.append(action, id);
            fetch('favorites.php', { method: 'POST', body: formData }); // Ignore response, just send

            setTimeout(() => btn.classList.remove('animating'), 400);
        }

        // --- INTERACTION: CART ANIMATION ---
        window.animateCart = function(btn) {
            btn.classList.add('animating');
            setTimeout(() => btn.classList.remove('animating'), 300);
        }

        // --- NAVBAR & HEADER ---
        window.addEventListener('scroll', () => {
            const navbar = document.querySelector('.navbar');
            if(window.scrollY > 50) navbar.classList.add('scrolled');
            else navbar.classList.remove('scrolled');
        });

        document.addEventListener('DOMContentLoaded', () => {
            // NEW: INQUIRY FORM LOADING ANIMATION
            const inquiryForm = document.getElementById('inquiryForm');
            if(inquiryForm) {
                inquiryForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    const btn = this.querySelector('button[type="submit"]');
                    const originalText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
                    
                    const formData = new FormData(this);
                    
                    fetch('inquire', { method: 'POST', body: formData })
                    .then(response => response.text())
                    .then(result => {
                        if(result.trim() === 'success') {
                            // CHANGED: Use showModalMessage instead of alert
                            showModalMessage('Sent!', 'Message sent successfully! We will get back to you soon.');
                            inquiryForm.reset();
                        } else {
                            alert('There was an error sending your message. Please try again.');
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('An unexpected error occurred.');
                    })
                    .finally(() => {
                        btn.disabled = false;
                        btn.innerHTML = originalText;
                    });
                });
            }

            // NEW: COMMISSION FORM HANDLER (AJAX)
            const commissionForm = document.getElementById('commissionForm');
            if(commissionForm) {
                commissionForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    const btn = this.querySelector('button[type="submit"]');
                    const originalText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
                    
                    const formData = new FormData(this);
                    
                    fetch('inquire', { method: 'POST', body: formData }) // Uses existing inquire.php
                    .then(response => response.text())
                    .then(result => {
                        if(result.trim() === 'success') {
                            closeModal('copyModal');
                            // SHOW NEW SUCCESS MODAL
                            document.getElementById('inquirySuccessModal').classList.add('active');
                            commissionForm.reset();
                        } else {
                            alert('There was an error sending your request. Please try again.');
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('An unexpected error occurred.');
                    })
                    .finally(() => {
                        btn.disabled = false;
                        btn.innerHTML = originalText;
                    });
                });
            }

            const notifBtn = document.getElementById('notifBtn');
            const notifDropdown = document.getElementById('notifDropdown');
            const userDropdown = document.querySelector('.user-dropdown');
            const profilePill = document.querySelector('.profile-pill');
            const notifBadge = document.getElementById('notifBadge');
            const notifList = document.getElementById('notifList');
            const markAllBtn = document.getElementById('markAllRead');

            if (profilePill) {
                profilePill.addEventListener('click', (e) => {
                    e.stopPropagation();
                    userDropdown.classList.toggle('active');
                    if (notifDropdown) notifDropdown.classList.remove('active');
                });
            }

            if (notifBtn) {
                notifBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    notifDropdown.classList.toggle('active');
                    if (userDropdown) userDropdown.classList.remove('active');
                });
                
                function fetchNotifications() {
                    fetch('fetch_notifications') 
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
                                        
                                        // Mark Read on Click
                                        item.addEventListener('click', (e) => {
                                            if (e.target.classList.contains('btn-notif-close')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('mark_as_read', { method: 'POST', body: formData }) 
                                                .then(() => fetchNotifications());
                                        });

                                        // Delete Notification
                                        item.querySelector('.btn-notif-close').addEventListener('click', (e) => {
                                            e.stopPropagation();
                                            if(!confirm('Delete this notification?')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('delete_notifications', { method: 'POST', body: formData }) 
                                                .then(res => res.json())
                                                .then(d => { if(d.status === 'success') fetchNotifications(); });
                                        });

                                        notifList.appendChild(item);
                                    });
                                }
                            }
                        });
                }

                if (markAllBtn) {
                    markAllBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        fetch('mark_all_as_read', { method: 'POST' }) 
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
            if (userDropdown) userDropdown.addEventListener('click', (e) => e.stopPropagation());
            if (notifDropdown) notifDropdown.addEventListener('click', (e) => e.stopPropagation());
        });

        // ==========================================
        // === MARQUEE LOGIC (DRAG & SCROLL ONLY) ===
        // ==========================================
        const marqueeTrack = document.getElementById('marqueeTrack');
        const marqueeWrapper = document.getElementById('marqueeWrapper');

        if (marqueeTrack && marqueeWrapper) {
            let scrollAmount = 0;
            // SLOWER SPEED: Reduced from 0.5 to 0.2
            let speed = 0.8; 
            let direction = 1; // 1 = Left
            let isHovered = false;
            let isDragging = false;
            let startX, startScrollLeft;

            // Clone content for infinite effect
            const originalContent = marqueeTrack.innerHTML;
            marqueeTrack.innerHTML += originalContent; // Duplicate once

            // Animation Loop
            function animateMarquee() {
                if (!isDragging && !isHovered) {
                    scrollAmount -= speed * direction;
                    const maxScroll = marqueeTrack.scrollWidth / 2;

                    // Wrap around logic
                    if (direction === 1 && Math.abs(scrollAmount) >= maxScroll) {
                        scrollAmount = 0;
                    } else if (direction === -1 && scrollAmount > 0) {
                        scrollAmount = -maxScroll;
                    }
                    
                    marqueeTrack.style.transform = `translateX(${scrollAmount}px)`;
                }
                requestAnimationFrame(animateMarquee);
            }
            // Start Loop
            requestAnimationFrame(animateMarquee);

            // Pause on Hover (Desktop)
            marqueeWrapper.addEventListener('mouseenter', () => { isHovered = true; });
            marqueeWrapper.addEventListener('mouseleave', () => { isHovered = false; isDragging = false; });

            // Touch / Mouse Drag Logic
            const startDrag = (e) => {
                isDragging = true;
                isHovered = true; // Pause auto scroll
                startX = e.pageX || e.touches[0].pageX;
                // Get current transform value
                const style = window.getComputedStyle(marqueeTrack);
                const matrix = new WebKitCSSMatrix(style.transform);
                startScrollLeft = matrix.m41;
            };

            const doDrag = (e) => {
                if (!isDragging) return;
                e.preventDefault();
                const x = e.pageX || e.touches[0].pageX;
                const walk = (x - startX) * 2; // Drag multiplier
                let newPos = startScrollLeft + walk;
                
                // Infinite Scroll Check during Drag
                const maxScroll = marqueeTrack.scrollWidth / 2;
                if (newPos > 0) newPos = -maxScroll;
                if (newPos < -maxScroll) newPos = 0;

                scrollAmount = newPos; // Sync state
                marqueeTrack.style.transform = `translateX(${newPos}px)`;
            };

            const endDrag = () => {
                isDragging = false;
                isHovered = false; // Resume
            };

            marqueeWrapper.addEventListener('mousedown', startDrag);
            marqueeWrapper.addEventListener('mousemove', doDrag);
            marqueeWrapper.addEventListener('mouseup', endDrag);
            
            marqueeWrapper.addEventListener('touchstart', startDrag);
            marqueeWrapper.addEventListener('touchmove', doDrag);
            marqueeWrapper.addEventListener('touchend', endDrag);
        }
    </script>

</body>
</html>
