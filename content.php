<?php
session_start();
include 'config.php';

// Security Check
if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// 1. Fetch Artworks
$artworks = [];
$sql_art = "SELECT a.*, 
            (SELECT COUNT(*) FROM favorites f WHERE f.artwork_id = a.id) as fav_count,
            (SELECT status FROM bookings b WHERE (b.artwork_id = a.id OR b.service = a.title) AND b.status IN ('approved', 'completed') ORDER BY b.id DESC LIMIT 1) as active_booking_status
            FROM artworks a 
            ORDER BY id DESC";
$res_art = mysqli_query($conn, $sql_art);
if ($res_art) while ($row = mysqli_fetch_assoc($res_art)) $artworks[] = $row;

// 2. Fetch Services
$services = [];
$res_serv = mysqli_query($conn, "SELECT * FROM services ORDER BY id DESC");
if ($res_serv) while ($row = mysqli_fetch_assoc($res_serv)) $services[] = $row;

// 3. Fetch Events
$events = [];
if($res_evt = mysqli_query($conn, "SELECT * FROM events ORDER BY event_date ASC")) {
    while ($row = mysqli_fetch_assoc($res_evt)) $events[] = $row;
}

// 4. Fetch Single Artist
$single_artist = null;
$res_artist = mysqli_query($conn, "SELECT * FROM artists LIMIT 1");
if ($res_artist && mysqli_num_rows($res_artist) > 0) {
    $single_artist = mysqli_fetch_assoc($res_artist);
}

// Time-based greeting
$hour = date('H');
if ($hour < 12) $greeting = "Good Morning";
elseif ($hour < 18) $greeting = "Good Afternoon";
else $greeting = "Good Evening";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Content | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        /* =========================================
           INLINED ADMIN THEME (Matches manage_news.php)
           ========================================= */
        :root {
            /* Base Colors */
            --bg-body: #f8f9fc;
            --text-main: #333333;
            --text-muted: #888888;
            --border-color: rgba(0,0,0,0.05);
            --card-bg: #ffffff;
            --shadow-color: rgba(0,0,0,0.05);
            --input-bg: #ffffff;

            /* Sidebar Colors */
            --sidebar-bg: #ffffff; 
            --sidebar-text: #666666;
            --sidebar-active-bg: #cd853f;
            --sidebar-active-text: #ffffff;
            --sidebar-hover: #fff5eb;
            --logo-color: #333333;
            
            /* Accents */
            --accent: #cd853f;
            --accent-hover: #b07236;
            
            /* Status Colors */
            --green: #10b981;
            --red: #ef4444;
            --blue: #3b82f6;
            --orange: #f59e0b;
            
            /* Dimensions */
            --sidebar-width: 280px;
            --radius-soft: 12px;
            
            /* Fonts */
            --font-head: 'Playfair Display', serif;
            --font-main: 'Nunito Sans', sans-serif;
            --font-script: 'Pacifico', cursive;
        }

        /* Dark Mode Overrides */
        [data-theme="dark"] {
            --bg-body: #121212;
            --text-main: #e0e0e0;
            --text-muted: #a0a0a0;
            --border-color: rgba(255,255,255,0.1);
            --card-bg: #1e1e1e;
            --shadow-color: rgba(0,0,0,0.3);
            --input-bg: #2a2a2a;
            --sidebar-bg: #1a1a1a; 
            --sidebar-text: #b0b0b0;
            --sidebar-active-bg: #cd853f;
            --sidebar-active-text: #ffffff;
            --sidebar-hover: #2c2c2c;
            --logo-color: #ffffff;
        }

        body {
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: var(--font-main);
            transition: background-color 0.3s ease, color 0.3s ease;
            margin: 0; padding: 0;
        }

        a { text-decoration: none; color: inherit; transition: 0.3s; }
        ul { list-style: none; padding: 0; margin: 0; }
        * { box-sizing: border-box; }

        /* === SIDEBAR === */
        .sidebar {
            position: fixed; top: 0; left: 0; bottom: 0;
            width: var(--sidebar-width);
            background: var(--sidebar-bg);
            padding: 30px 20px;
            display: flex; flex-direction: column;
            border-right: 1px solid var(--border-color);
            box-shadow: 5px 0 25px var(--shadow-color);
            z-index: 1000;
            transition: all 0.3s ease;
        }

        .sidebar-header {
            text-align: center; margin-bottom: 40px; padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .sidebar-logo {
            text-decoration: none; display: flex; flex-direction: column; align-items: center; line-height: 1;
        }
        .logo-top { font-family: var(--font-head); font-size: 0.85rem; font-weight: 700; color: var(--text-muted); letter-spacing: 2px; margin-bottom: -5px; }
        .logo-main { font-family: var(--font-script); font-size: 3rem; font-weight: 400; color: var(--logo-color); transform: rotate(-4deg); text-shadow: 0 3px 6px rgba(0,0,0,0.15); margin: 0; padding: 5px 0; }
        .logo-red { color: #ff4d4d; }
        .logo-bottom { font-family: var(--font-main); font-size: 0.75rem; font-weight: 800; color: var(--text-muted); letter-spacing: 8px; text-transform: uppercase; margin-top: -2px; margin-right: -8px; }

        .sidebar-nav { flex: 1; overflow-y: auto; }
        .sidebar-nav li { margin-bottom: 8px; }
        .sidebar-nav a {
            display: flex; align-items: center; gap: 15px; padding: 14px 20px;
            color: var(--sidebar-text); font-weight: 700; font-size: 0.95rem;
            border-radius: var(--radius-soft); transition: all 0.3s ease;
        }
        .sidebar-nav a i { width: 20px; text-align: center; font-size: 1.1rem; opacity: 0.7; }
        .sidebar-nav a:hover { background: var(--sidebar-hover); color: var(--accent); transform: translateX(3px); }
        .sidebar-nav a:hover i { color: var(--accent); opacity: 1; }
        .sidebar-nav li.active a { background: var(--sidebar-active-bg); color: var(--sidebar-active-text); box-shadow: 0 4px 12px rgba(205, 133, 63, 0.3); }
        .sidebar-nav li.active a i { color: var(--sidebar-active-text); opacity: 1; }

        .sidebar-footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); }
        .btn-logout {
            display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%;
            padding: 12px; background: rgba(255, 77, 77, 0.1); color: #ff4d4d;
            border-radius: var(--radius-soft); font-weight: 700; transition: 0.3s;
        }
        .btn-logout:hover { background: #ff4d4d; color: white; transform: translateY(-2px); box-shadow: 0 4px 10px rgba(255, 77, 77, 0.2); }

        /* === MAIN CONTENT === */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 30px 40px;
            width: calc(100% - var(--sidebar-width));
        }

        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .page-header h1 { font-family: var(--font-head); font-size: 2.2rem; color: var(--text-main); margin: 0 0 5px 0; }
        .page-header p { color: var(--text-muted); font-size: 1rem; margin: 0; }

        .header-actions { display: flex; align-items: center; gap: 20px; }
        .icon-btn {
            background: var(--card-bg); width: 45px; height: 45px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem; color: var(--text-muted); cursor: pointer; border: 1px solid var(--border-color);
            transition: 0.3s; box-shadow: 0 2px 5px var(--shadow-color);
        }
        .icon-btn:hover { color: var(--accent); transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }

        .user-profile {
            display: flex; align-items: center; gap: 15px; background: var(--card-bg);
            padding: 6px 6px 6px 20px; border-radius: 50px; border: 1px solid var(--border-color);
            box-shadow: 0 2px 5px var(--shadow-color);
        }
        .profile-info { text-align: right; line-height: 1.2; }
        .profile-info .name { display: block; font-weight: 800; font-size: 0.9rem; color: var(--text-main); }
        .profile-info .role { font-size: 0.75rem; color: var(--accent); font-weight: 700; text-transform: uppercase; }
        .avatar img { width: 40px; height: 40px; border-radius: 50%; border: 2px solid var(--bg-body); }

        /* === CONTENT PAGE SPECIFIC === */
        
        /* Tabs */
        .tabs { margin-bottom: 30px; display: flex; gap: 10px; flex-wrap: wrap; border-bottom: 2px solid var(--border-color); padding-bottom: 5px; }
        .tab-btn { 
            background: none; border: none; padding: 12px 20px; 
            font-size: 1rem; font-weight: 700; color: var(--text-muted); 
            cursor: pointer; transition: 0.3s; border-bottom: 3px solid transparent; margin-bottom: -7px;
            display: flex; align-items: center; gap: 8px; font-family: var(--font-main);
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-pane { display: none; animation: fadeIn 0.3s ease; }
        .tab-pane.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        /* Layouts */
        .grid-layout { display: grid; grid-template-columns: 350px 1fr; gap: 30px; }
        .single-layout { display: block; max-width: 800px; margin: 0 auto; }
        
        .card { background: var(--card-bg); border-radius: var(--radius-soft); box-shadow: 0 5px 15px var(--shadow-color); padding: 25px; border: 1px solid var(--border-color); }
        .card-header h3 { color: var(--text-main); font-family: var(--font-head); margin-bottom: 20px; font-size: 1.3rem; margin-top: 0; }

        /* Controls */
        .controls-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
        .search-wrapper { position: relative; width: 100%; max-width: 400px; display: flex; gap: 10px; }
        .search-wrapper input { 
            width: 100%; padding: 12px 15px 12px 45px; border-radius: 50px; 
            border: 1px solid var(--border-color); outline: none; background: var(--input-bg); 
            color: var(--text-main); font-family: var(--font-main);
        }
        .search-wrapper i { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-muted); }
        .btn-search { 
            background: var(--accent); color: white; padding: 0 25px; border-radius: 50px; 
            border: none; font-weight: 700; cursor: pointer; transition: 0.2s; white-space: nowrap; display: flex; align-items: center; gap: 8px;
        }
        .btn-search:hover { background: var(--accent-hover); transform: translateY(-2px); }

        /* Forms */
        .form-group { margin-bottom: 18px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 18px; }
        .form-group label { display: block; margin-bottom: 6px; font-weight: 700; font-size: 0.85rem; color: var(--text-muted); }
        .form-control, input[type="text"], input[type="number"], input[type="date"], input[type="time"], input[type="file"], select, textarea {
            width: 100%; padding: 12px 15px; border: 1px solid var(--border-color); 
            border-radius: 8px; background: var(--input-bg); color: var(--text-main); 
            font-size: 0.95rem; outline: none; transition: 0.3s; font-family: var(--font-main);
        }
        .form-control:focus, input:focus, select:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(205, 133, 63, 0.1); }
        
        .btn-primary { width: 100%; padding: 14px; background: var(--accent); color: white; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.2s; margin-top: 10px; font-size: 1rem; }
        .btn-primary:hover { background: var(--accent-hover); transform: translateY(-2px); box-shadow: 0 5px 15px rgba(205, 133, 63, 0.2); }
        .btn-text { width: 100%; background: none; border: none; color: var(--text-muted); padding: 10px; cursor: pointer; margin-top: 5px; font-weight: 600; text-decoration: underline; }
        .btn-text:hover { color: var(--red); }

        /* Tables */
        .table-responsive { overflow-x: auto; }
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th { text-align: left; padding: 18px 25px; background: var(--bg-body); color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border-color); font-weight: 700; }
        .styled-table td { padding: 18px 25px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        .styled-table tr:hover { background: rgba(0,0,0,0.02); }

        .thumb-img { width: 60px; height: 60px; border-radius: 8px; object-fit: cover; border: 1px solid var(--border-color); }
        .artist-avatar { width: 150px; height: 150px; border-radius: 50%; object-fit: cover; border: 4px solid var(--accent); margin-bottom: 25px; display: block; margin-left: auto; margin-right: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.1); }
        
        .item-title { font-weight: 700; color: var(--text-main); font-size: 1rem; margin-bottom: 4px; }
        .item-meta { font-size: 0.85rem; color: var(--text-muted); display: block; }

        /* Actions */
        .actions { display: flex; gap: 8px; }
        .btn-icon { width: 32px; height: 32px; border-radius: 6px; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: 0.2s; }
        .btn-icon.edit { background: rgba(59, 130, 246, 0.1); color: var(--blue); }
        .btn-icon.delete { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .btn-icon:hover { transform: translateY(-2px); opacity: 0.8; }

        /* Status Badges */
        .status-badge { padding: 5px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; display: inline-block; margin-bottom: 5px; }
        .status-available { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        .status-reserved { background: rgba(245, 158, 11, 0.1); color: var(--orange); }
        .status-sold { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .fav-count { font-size: 0.8rem; color: var(--red); font-weight: 600; display: flex; align-items: center; gap: 5px; }

        /* Notifications & Modals */
        .notif-wrapper { position: relative; }
        .notif-bell .dot { position: absolute; top: 0; right: 0; background: #ff4d4d; color: white; font-size: 0.6rem; font-weight: 700; border-radius: 50%; min-width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border: 2px solid var(--card-bg); }
        .notif-dropdown { display: none; position: absolute; right: -10px; top: 60px; width: 320px; background: var(--card-bg); border-radius: 12px; box-shadow: 0 15px 40px rgba(0,0,0,0.15); border: 1px solid var(--border-color); z-index: 1100; overflow: hidden; }
        .notif-dropdown.active { display: block; }
        .notif-header { padding: 15px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; font-weight: 700; color: var(--text-main); background: var(--bg-body); }
        .notif-list { max-height: 300px; overflow-y: auto; }
        .notif-item { padding: 15px; border-bottom: 1px solid var(--border-color); cursor: pointer; transition: 0.2s; color: var(--text-main); }
        .notif-item:hover { background: var(--bg-body); }
        .notif-item.unread { border-left: 3px solid var(--accent); background: rgba(205, 133, 63, 0.05); }
        .no-notif { padding: 20px; text-align: center; color: var(--text-muted); font-style: italic; }
        .small-btn { background: none; border: none; color: var(--accent); font-weight: 700; font-size: 0.75rem; cursor: pointer; text-transform: uppercase; }
        .btn-notif-close { background: none; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; position: absolute; top:12px; right:12px; }
        .btn-notif-close:hover { color: #ff4d4d; }

        /* Modals */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        .modal-card { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); }
        .modal-card.small { width: 400px; max-width: 90%; border-radius: 16px; padding: 35px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.2); transform: translateY(20px); transition: 0.3s; }
        .modal-overlay.active .modal-card.small { transform: translateY(0); }
        .modal-header-icon { width: 70px; height: 70px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        .delete-icon { background: rgba(239, 68, 68, 0.1); color: var(--red); }
        .success-icon { background: rgba(16, 185, 129, 0.1); color: var(--green); }
        
        .modal-card h3 { font-family: var(--font-head); font-size: 1.5rem; margin-bottom: 10px; color: var(--text-main); }
        .modal-card p { color: var(--text-muted); }
        .btn-group { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
        .btn-friendly { padding: 12px 25px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; font-size: 0.95rem; font-family: var(--font-main); }
        .btn-friendly:hover { transform: translateY(-2px); opacity: 0.9; }

        @media (max-width: 1024px) {
            .grid-layout { grid-template-columns: 1fr; }
            .sidebar { width: 80px; padding: 20px 10px; }
            .sidebar-logo span:not(.logo-main), .logo-bottom, .sidebar-nav span, .sidebar-footer span { display: none; }
            .logo-main { font-size: 1.5rem; transform: rotate(0); }
            .sidebar-nav a { justify-content: center; padding: 15px; }
            .main-content { margin-left: 80px; width: calc(100% - 80px); }
        }
    </style>
</head>
<body>
    <script>
        (function() {
            const savedTheme = localStorage.getItem('adminTheme');
            if (savedTheme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
            }
        })();
    </script>

    <aside class="sidebar">
        <div class="sidebar-header">
            <a href="index.php" class="sidebar-logo">
                <span class="logo-top">THE</span>
                <span class="logo-main"><span class="logo-red">M</span>an<span class="logo-red">C</span>ave</span>
                <span class="logo-bottom">GALLERY</span>
            </a>
        </div>
        <nav class="sidebar-nav">
            <ul>
                <li><a href="admin.php"><i class="fas fa-home"></i> <span>Dashboard</span></a></li>
                <li><a href="reservations.php"><i class="fas fa-calendar-check"></i> <span>Appointments</span></a></li>
                <li class="active"><a href="content.php"><i class="fas fa-layer-group"></i> <span>Website Content</span></a></li>
                <li><a href="manage_hero.php"><i class="fas fa-images"></i> <span>Manage Slider</span></a></li>
                <li><a href="manage_news.php"><i class="fas fa-newspaper"></i> <span>Gallery Updates</span></a></li>
                <li><a href="manage_team.php"><i class="fas fa-user-tie"></i> <span>Manage Artists</span></a></li>
                <li><a href="manage_about_artists.php"><i class="fas fa-users-cog"></i> <span>About: Meet Artists</span></a></li>
                <li><a href="users.php"><i class="fas fa-users"></i> <span>Customers & Staff</span></a></li>
                <li><a href="feedback.php"><i class="fas fa-comments"></i> <span>Message & Feedback</span></a></li>
                <li><a href="trash.php"><i class="fas fa-trash-alt"></i> <span>Recycle Bin</span></a></li>
            </ul>
        </nav>
        <div class="sidebar-footer">
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Logout</span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="top-bar">
            <div class="page-header">
                <h1>Website Content</h1>
                <p>Manage inventory, services, events, and artists.</p>
            </div>
            
            <div class="header-actions">
                <button class="icon-btn" id="themeToggle" title="Toggle Dark Mode">
                    <i class="fas fa-moon"></i>
                </button>

                <div class="notif-wrapper">
                    <div class="icon-btn notif-bell" id="adminNotifBtn">
                        <i class="far fa-bell"></i>
                        <span class="dot" id="adminNotifBadge" style="display:none;">0</span>
                    </div>
                    
                    <div class="notif-dropdown" id="adminNotifDropdown">
                        <div class="notif-header">
                            <span>Notifications</span>
                            <button id="adminMarkAllRead" class="small-btn">Mark all read</button>
                        </div>
                        <ul class="notif-list" id="adminNotifList">
                            <li class="no-notif">Loading...</li>
                        </ul>
                    </div>
                </div>

                <div class="user-profile">
                    <div class="profile-info">
                        <span class="name">Administrator</span>
                        <span class="role">Super Admin</span>
                    </div>
                    <div class="avatar"><img src="https://ui-avatars.com/api/?name=Admin&background=cd853f&color=fff" alt="Admin"></div>
                </div>
            </div>
        </header>

        <div class="controls-bar">
            <div class="search-wrapper">
                <i class="fas fa-search"></i>
                <input type="text" id="globalSearch" placeholder="Search artworks, services, etc...">
                <button class="btn-search" onclick="triggerSearch()"><i class="fas fa-arrow-right"></i> Search</button>
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" id="tab-artworks" onclick="switchTab('artworks', this)"><i class="fas fa-paint-brush"></i> Artworks</button>
            <button class="tab-btn" id="tab-services" onclick="switchTab('services', this)"><i class="fas fa-concierge-bell"></i> Services</button>
            <button class="tab-btn" id="tab-events" onclick="switchTab('events', this)"><i class="fas fa-calendar-alt"></i> Upcoming Events</button>
            <button class="tab-btn" id="tab-artists" onclick="switchTab('artists', this)"><i class="fas fa-user-friends"></i> Artist Profile</button>
        </div>

        <div id="artworks" class="tab-pane active">
            <div class="grid-layout">
                <div class="card form-card">
                    <div class="card-header"><h3 id="artFormTitle">Add New Artwork</h3></div>
                    <form id="artworkForm" enctype="multipart/form-data">
                        <input type="hidden" id="art-id" name="id">
                        
                        <div class="form-group">
                            <label>Artwork Title</label>
                            <input type="text" id="art-title" name="title" required placeholder="e.g., Starry Night">
                        </div>
                        
                        <div class="form-group">
                            <label>Artist</label>
                            <input type="text" id="art-artist" name="artist" required placeholder="Artist Name" value="<?php echo htmlspecialchars($single_artist['name'] ?? ''); ?>">
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Medium</label>
                                <input type="text" id="art-medium" name="medium" placeholder="e.g. Canvas, Paper">
                            </div>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label>Dimensions (WxH)</label>
                                <div style="display:flex; gap:10px; align-items:center;">
                                    <input type="text" id="art-width" name="width" required class="form-control" placeholder="Width (e.g. 24)">
                                    <span style="font-weight:bold; color:var(--text-muted);">x</span>
                                    <input type="text" id="art-height" name="height" required class="form-control" placeholder="Height (e.g. 36)">
                                </div>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Depth & Unit</label>
                                <div style="display:flex; gap:10px; align-items:center;">
                                    <input type="text" id="art-depth" name="depth" class="form-control" placeholder="Depth (Optional)">
                                    <input type="text" id="art-size-type" name="unit" required class="form-control" placeholder="Unit (e.g. inches, cm)">
                                </div>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Year</label>
                                <input type="text" id="art-year" name="year" placeholder="YYYY" maxlength="4">
                            </div>
                            <div class="form-group">
                                <label>Price (PHP)</label>
                                <input type="number" id="art-price" name="price" step="0.01" min="0" required placeholder="0.00">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label>Availability Status</label>
                            <select id="art-status" name="status" class="form-control" required>
                                <option value="Available">Available</option>
                                <option value="Reserved">Reserved</option>
                                <option value="Sold">Sold</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label>Description</label>
                            <textarea id="art-desc" name="description" rows="3"></textarea>
                        </div>
                        <div class="form-group">
                            <label>Upload Image (Max 30MB)</label>
                            <input type="file" id="art-img" name="image" accept="image/*" style="padding: 10px;">
                        </div>
                        <button type="submit" class="btn-primary" id="art-btn-text">Save Artwork</button>
                        <button type="button" id="cancelArtEdit" class="btn-text" style="display:none;" onclick="resetArtForm()">Cancel Edit</button>
                    </form>
                </div>

                <div class="card list-card">
                    <div class="card-header"><h3>Current Inventory</h3></div>
                    <div class="table-responsive">
                        <table class="styled-table">
                            <thead><tr><th>Image</th><th>Details</th><th>Stats/Status</th><th>Actions</th></tr></thead>
                            <tbody>
                                <?php foreach ($artworks as $art): 
                                    $img = !empty($art['image_path']) ? 'uploads/'.$art['image_path'] : 'https://placehold.co/50'; 
                                    $displaySize = htmlspecialchars($art['size'] ?? 'N/A');
                                    $displaySize = str_replace('x 0', '', $displaySize);
                                    $status = $art['status'] ?? 'Available';
                                    if(isset($art['active_booking_status']) && $art['active_booking_status'] === 'approved') $status = 'Reserved';
                                    if(isset($art['active_booking_status']) && $art['active_booking_status'] === 'completed') $status = 'Sold';
                                    $statusClass = 'status-' . strtolower($status);
                                    $favCount = $art['fav_count'] ?? 0;
                                ?>
                                <tr id="art-row-<?= $art['id'] ?>">
                                    <td><img src="<?= htmlspecialchars($img) ?>" class="thumb-img"></td>
                                    <td>
                                        <div class="item-title"><?= htmlspecialchars($art['title']) ?></div>
                                        <span class="item-meta">By <?= htmlspecialchars($art['artist']) ?></span>
                                        <span class="item-meta"><?= $displaySize ?></span>
                                    </td>
                                    <td>
                                        <span class="status-badge <?= $statusClass ?>"><?= htmlspecialchars($status) ?></span>
                                        <div class="fav-count"><i class="fas fa-heart"></i> <?= $favCount ?></div>
                                    </td>
                                    <td>
                                        <div class="actions">
                                            <button class="btn-icon edit" onclick='editArtwork(<?= json_encode($art) ?>)'><i class="fas fa-pen"></i></button>
                                            <button class="btn-icon delete" onclick="confirmDelete('artwork', <?= $art['id'] ?>)"><i class="fas fa-trash"></i></button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div id="services" class="tab-pane">
            <div class="grid-layout">
                <div class="card form-card">
                    <div class="card-header"><h3 id="serviceFormTitle">Manage Service</h3></div>
                    <form id="serviceForm">
                        <input type="hidden" id="service-id" name="id">
                        <div class="form-group">
                            <label>Service Name</label>
                            <input type="text" id="service-name" name="name" required placeholder="e.g., Art Appraisal">
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Price (PHP)</label>
                                <input type="number" id="service-price" name="price" step="0.01" min="0" required placeholder="0.00">
                            </div>
                            <div class="form-group">
                                <label>Duration</label>
                                <input type="text" id="service-duration" name="duration" required placeholder="e.g. 2 Hours">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea id="service-desc" name="description" rows="3" placeholder="Brief details about the service..."></textarea>
                        </div>
                        <button type="submit" class="btn-primary" id="service-btn-text">Save Service</button>
                        <button type="button" id="cancelServiceEdit" class="btn-text" style="display:none;" onclick="resetServiceForm()">Cancel</button>
                    </form>
                </div>

                <div class="card list-card">
                    <div class="card-header"><h3>Gallery Services</h3></div>
                    <div class="table-responsive">
                        <table class="styled-table">
                            <thead>
                                <tr><th>Service Info</th><th>Price</th><th>Duration</th><th>Actions</th></tr>
                            </thead>
                            <tbody>
                                <?php foreach ($services as $srv): ?>
                                <tr id="srv-row-<?= $srv['id'] ?>">
                                    <td>
                                        <div class="item-title"><?= htmlspecialchars($srv['name']) ?></div>
                                        <span class="item-meta"><?= htmlspecialchars(substr($srv['description'], 0, 50)) . (strlen($srv['description']) > 50 ? '...' : '') ?></span>
                                    </td>
                                    <td style="color:var(--accent); font-weight:700;">₱<?= number_format($srv['price']) ?></td>
                                    <td><?= htmlspecialchars($srv['duration']) ?></td>
                                    <td>
                                        <div class="actions">
                                            <button class="btn-icon edit" onclick='editService(<?= json_encode($srv) ?>)'><i class="fas fa-pen"></i></button>
                                            <button class="btn-icon delete" onclick="confirmDelete('service', <?= $srv['id'] ?>)"><i class="fas fa-trash"></i></button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div id="events" class="tab-pane">
            <div class="grid-layout">
                <div>
                    <!-- NEW: Manage Section Image -->
                    <div class="card form-card mb-4" style="margin-bottom: 20px;">
                        <div class="card-header"><h3>Manage Section Image</h3></div>
                        <form action="manage_events.php" method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="action" value="upload_section_image">
                            <div class="form-group">
                                <label>Upload Section Image (JPG/PNG)</label>
                                <input type="file" name="section_image" accept="image/*" required style="padding:10px;">
                            </div>
                            <button type="submit" class="btn-primary">Update Image</button>
                        </form>
                    </div>

                    <!-- Existing: Add/Edit Event -->
                    <div class="card form-card">
                        <div class="card-header"><h3 id="eventFormTitle">Add Event</h3></div>
                        <form id="eventForm">
                        <input type="hidden" id="event-id" name="id">
                        <input type="hidden" name="action" value="save">
                        <div class="form-group">
                            <label>Event Title</label>
                            <input type="text" id="event-title" name="title" required placeholder="e.g. Modern Abstract Night">
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Date</label>
                                <input type="date" id="event-date" name="event_date" required>
                            </div>
                            <div class="form-group">
                                <label>Time</label>
                                <input type="time" id="event-time" name="event_time" required>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Location</label>
                            <input type="text" id="event-location" name="location" placeholder="e.g. Main Gallery Hall">
                        </div>
                        <button type="submit" class="btn-primary" id="event-btn-text">Publish Event</button>
                        <button type="button" id="cancelEventEdit" class="btn-text" style="display:none;" onclick="resetEventForm()">Cancel</button>
                    </form>
                </div>
            </div>

                <div class="card list-card">
                    <div class="card-header"><h3>Upcoming Events</h3></div>
                    <div class="table-responsive">
                        <table class="styled-table">
                            <thead><tr><th>Date</th><th>Event Details</th><th>Actions</th></tr></thead>
                            <tbody>
                                <?php foreach ($events as $evt): ?>
                                <tr id="evt-row-<?= $evt['id'] ?>">
                                    <td>
                                        <div class="item-title" style="color:var(--accent);"><?= date('M d', strtotime($evt['event_date'])) ?></div>
                                        <span class="item-meta"><?= date('Y', strtotime($evt['event_date'])) ?></span>
                                    </td>
                                    <td>
                                        <div class="item-title"><?= htmlspecialchars($evt['title']) ?></div>
                                        <span class="item-meta"><i class="far fa-clock"></i> <?= htmlspecialchars($evt['event_time']) ?> | <i class="fas fa-map-marker-alt"></i> <?= htmlspecialchars($evt['location']) ?></span>
                                    </td>
                                    <td>
                                        <div class="actions">
                                            <button class="btn-icon edit" onclick='editEvent(<?= json_encode($evt) ?>)'><i class="fas fa-pen"></i></button>
                                            <button class="btn-icon delete" onclick="confirmDelete('event', <?= $evt['id'] ?>)"><i class="fas fa-trash"></i></button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div id="artists" class="tab-pane">
            <div class="single-layout">
                <div class="card form-card">
                    <div class="card-header"><h3 id="artistFormTitle">Manage Artist Profile</h3></div>
                    
                    <div style="text-align:center; padding: 20px 0;">
                        <?php 
                            $defaultAvatar = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png';
                            $avatar = !empty($single_artist['image_path']) ? 'uploads/'.$single_artist['image_path'] : $defaultAvatar;
                        ?>
                        <img src="<?php echo htmlspecialchars($avatar); ?>" class="artist-avatar" alt="Profile">
                        <p style="color:var(--text-muted); font-style:italic;">"The Artist displayed on the homepage"</p>
                    </div>

                    <form id="artistForm" enctype="multipart/form-data">
                        <input type="hidden" id="artist-id" name="id" value="<?php echo $single_artist['id'] ?? ''; ?>">
                        <input type="hidden" name="action" value="save">
                        
                        <div class="form-group">
                            <label>Artist Name</label>
                            <input type="text" id="artist-name" name="name" required placeholder="e.g. Elena Vance" value="<?php echo htmlspecialchars($single_artist['name'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Art Style / Title</label>
                            <input type="text" id="artist-style" name="style" placeholder="e.g. Abstract Expressionism" value="<?php echo htmlspecialchars($single_artist['style'] ?? ''); ?>">
                        </div>
                        <div class="form-group">
                            <label>Quote</label>
                            <textarea id="artist-quote" name="quote" rows="2" placeholder="Inspiring quote..."><?php echo htmlspecialchars($single_artist['quote'] ?? ''); ?></textarea>
                        </div>
                        <div class="form-group">
                            <label>Biography</label>
                            <textarea id="artist-bio" name="bio" rows="6" placeholder="Artist background..."><?php echo htmlspecialchars($single_artist['bio'] ?? ''); ?></textarea>
                        </div>
                        <div class="form-group">
                            <label>Update Profile Image</label>
                            <input type="file" id="artist-img" name="image" accept="image/*" style="padding: 10px;">
                        </div>
                        <button type="submit" class="btn-primary" id="artist-btn-text">Update Profile</button>
                    </form>
                </div>
            </div>
        </div>

    </main>

    <div class="modal-overlay" id="confirmModal">
        <div class="modal-card small">
            <div class="modal-header-icon delete-icon"><i class="fas fa-trash-alt"></i></div>
            <h3 id="confirmTitle">Delete Item?</h3>
            <p id="confirmText">Are you sure you want to move this to the recycle bin?</p>
            <div class="btn-group">
                <button class="btn-friendly" style="background:var(--border-color); color:var(--text-main);" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn-friendly" id="confirmBtnAction" style="background:#ef4444; color:white;">Delete</button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="alertModal">
        <div class="modal-card small">
            <div class="modal-header-icon success-icon" id="alertIcon"><i class="fas fa-check"></i></div>
            <h3 id="alertTitle">Success!</h3>
            <p id="alertMessage">Action completed successfully.</p>
            <button class="btn-friendly" style="background:var(--text-main); color:var(--bg-body); width:100%;" onclick="closeModal('alertModal');">Okay</button>
        </div>
    </div>

    <script>
        // === THEME & NOTIFICATION LOGIC ===
        document.addEventListener('DOMContentLoaded', () => {
            // Theme Toggle
            const themeToggleBtn = document.getElementById('themeToggle');
            const themeIcon = themeToggleBtn.querySelector('i');
            const savedTheme = localStorage.getItem('adminTheme');
            if (savedTheme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
                themeIcon.classList.replace('fa-moon', 'fa-sun');
            }

            themeToggleBtn.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                if (currentTheme === 'dark') {
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('adminTheme', 'light');
                    themeIcon.classList.replace('fa-sun', 'fa-moon');
                } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                    localStorage.setItem('adminTheme', 'dark');
                    themeIcon.classList.replace('fa-moon', 'fa-sun');
                }
            });

            // Tab Memory
            const activeTabId = localStorage.getItem('adminActiveTab') || 'artworks';
            const btn = document.getElementById('tab-' + activeTabId);
            if(btn) switchTab(activeTabId, btn);

            // Search
            const searchInput = document.getElementById('globalSearch');
            if(searchInput) {
                searchInput.addEventListener('keyup', function(e) {
                    if (e.key === 'Enter') triggerSearch();
                    else filterRows(this.value);
                });
            }

            // Notifications logic...
            const notifBtn = document.getElementById('adminNotifBtn');
            const notifDropdown = document.getElementById('adminNotifDropdown');
            const notifBadge = document.getElementById('adminNotifBadge');
            const notifList = document.getElementById('adminNotifList');
            const markAllBtn = document.getElementById('adminMarkAllRead');

            if(notifBtn) {
                notifBtn.addEventListener('click', (e) => { e.stopPropagation(); notifDropdown.classList.toggle('active'); });
                function fetchNotifications() {
                    fetch('fetch_notifications.php').then(res => res.json()).then(data => {
                        if (data.status === 'success') {
                            if (data.unread_count > 0) { notifBadge.innerText = data.unread_count; notifBadge.style.display = 'flex'; }
                            else { notifBadge.style.display = 'none'; }
                            notifList.innerHTML = '';
                            if (data.notifications.length === 0) notifList.innerHTML = '<li class="no-notif">No new notifications</li>';
                            else {
                                data.notifications.forEach(notif => {
                                    const li = document.createElement('li');
                                    li.className = `notif-item ${notif.is_read == 0 ? 'unread' : ''}`;
                                    li.innerHTML = `<div class="notif-msg">${notif.message}</div><div class="notif-time">${notif.created_at}</div><button class="btn-notif-close">&times;</button>`;
                                    li.addEventListener('click', () => { fetch('mark_as_read.php', { method: 'POST', body: new FormData().append('id', notif.id) }).then(() => fetchNotifications()); });
                                    notifList.appendChild(li);
                                });
                            }
                        }
                    });
                }
                if (markAllBtn) markAllBtn.addEventListener('click', (e) => { e.stopPropagation(); fetch('mark_all_as_read.php', { method: 'POST' }).then(() => fetchNotifications()); });
                window.addEventListener('click', () => { if (notifDropdown.classList.contains('active')) notifDropdown.classList.remove('active'); });
                fetchNotifications();
                setInterval(fetchNotifications, 30000);
            }
        });

        // Tab Switcher
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
            localStorage.setItem('adminActiveTab', tabId);
            document.getElementById('globalSearch').value = '';
            filterRows('');
        }

        // Search Logic
        function triggerSearch() { filterRows(document.getElementById('globalSearch').value); }
        function filterRows(val) {
            val = val.toLowerCase();
            const activePane = document.querySelector('.tab-pane.active');
            if(activePane) {
                const rows = activePane.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const text = row.innerText.toLowerCase();
                    row.style.display = text.includes(val) ? '' : 'none';
                });
            }
        }

        // Modal Logic
        let deleteCallback = null;
        function closeModal(id) { document.getElementById(id).classList.remove('active'); }
        function showAlert(title, msg, type, reload = false) {
            document.getElementById('alertTitle').innerText = title;
            document.getElementById('alertMessage').innerText = msg;
            const icon = document.getElementById('alertIcon');
            if (type === 'success') { icon.className = 'modal-header-icon success-icon'; icon.innerHTML = '<i class="fas fa-check"></i>'; }
            else { icon.className = 'modal-header-icon delete-icon'; icon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>'; }
            const btn = document.querySelector('#alertModal button');
            btn.onclick = function() { closeModal('alertModal'); if (reload) location.reload(); };
            document.getElementById('alertModal').classList.add('active');
        }

        function confirmDelete(type, id) {
            document.getElementById('confirmTitle').innerText = 'Delete Item?';
            document.getElementById('confirmText').innerText = 'Are you sure you want to move this to the recycle bin?';
            if (type === 'artwork') deleteCallback = () => performDelete('artworks.php?action=delete', id);
            else if (type === 'service') deleteCallback = () => performDelete('services.php?action=delete', id);
            else if (type === 'event') deleteCallback = () => performDelete('manage_events.php', id, true);
            else if (type === 'artist') deleteCallback = () => performDelete('manage_artists.php', id, true);
            document.getElementById('confirmModal').classList.add('active');
        }

        document.getElementById('confirmBtnAction').addEventListener('click', () => { if (deleteCallback) deleteCallback(); closeModal('confirmModal'); });

        async function performDelete(url, id, isPostAction = false) {
            const formData = new FormData();
            formData.append('id', id);
            if (isPostAction) formData.append('action', 'delete');
            try {
                const res = await fetch(url, { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) showAlert('Deleted!', 'Item moved to trash.', 'success', true);
                else showAlert('Error', data.message || 'Could not delete item.', 'error');
            } catch (err) { showAlert('Error', 'Request failed.', 'error'); }
        }

        // --- ARTWORK FORM LOGIC ---
        const artForm = document.getElementById('artworkForm');
        artForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(artForm);
            
            // Construct 'size' string
            const w = document.getElementById('art-width').value;
            const h = document.getElementById('art-height').value;
            const d = document.getElementById('art-depth').value;
            const u = document.getElementById('art-size-type').value;
            let sizeStr = `${w} x ${h}`;
            if (d && d.trim() !== '') sizeStr += ` x ${d}`;
            sizeStr += ` ${u}`;
            formData.append('size', sizeStr);

            const action = document.getElementById('art-id').value ? 'update' : 'add';
            if(action === 'update') formData.append('id', document.getElementById('art-id').value);
            
            try {
                const res = await fetch(`artworks.php?action=${action}`, { method: 'POST', body: formData });
                const data = await res.json();
                if(data.success) showAlert('Success!', 'Artwork saved.', 'success', true);
                else showAlert('Error', data.message, 'error');
            } catch(err) { showAlert('Error', 'Request failed.', 'error'); }
        });

        function editArtwork(art) {
            document.getElementById('art-id').value = art.id;
            document.getElementById('art-title').value = art.title;
            document.getElementById('art-artist').value = art.artist; 
            document.getElementById('art-price').value = art.price;
            document.getElementById('art-desc').value = art.description;
            document.getElementById('art-status').value = art.status || 'Available';
            if(art.medium) document.getElementById('art-medium').value = art.medium;
            if(art.year) document.getElementById('art-year').value = art.year;
            
            if (art.size) {
                const parts = art.size.split(' x ');
                if (parts.length >= 2) {
                    document.getElementById('art-width').value = parts[0].trim();
                    let rest = parts[1].trim();
                    let depth = '', unit = '';
                    if (parts.length > 2) {
                        document.getElementById('art-height').value = parts[1].trim();
                        let lastPart = parts[2].trim();
                        let spaceIndex = lastPart.indexOf(' ');
                        if (spaceIndex > 0) { depth = lastPart.substring(0, spaceIndex); unit = lastPart.substring(spaceIndex + 1); } 
                        else { depth = lastPart; }
                    } else {
                        let spaceIndex = rest.indexOf(' ');
                        if (spaceIndex > 0) { document.getElementById('art-height').value = rest.substring(0, spaceIndex); unit = rest.substring(spaceIndex + 1); } 
                        else { document.getElementById('art-height').value = rest; }
                    }
                    document.getElementById('art-depth').value = depth;
                    document.getElementById('art-size-type').value = unit;
                } else { document.getElementById('art-width').value = art.size; }
            }
            document.getElementById('artFormTitle').textContent = 'Edit Artwork';
            document.getElementById('art-btn-text').textContent = 'Update Artwork';
            document.getElementById('cancelArtEdit').style.display = 'block';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function resetArtForm() {
            artForm.reset();
            document.getElementById('art-id').value = '';
            document.getElementById('artFormTitle').textContent = 'Add New Artwork';
            document.getElementById('art-btn-text').textContent = 'Save Artwork';
            document.getElementById('cancelArtEdit').style.display = 'none';
        }

        // --- SERVICE LOGIC ---
        const serviceForm = document.getElementById('serviceForm');
        serviceForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(serviceForm);
            const action = document.getElementById('service-id').value ? 'update' : 'add';
            try {
                const res = await fetch(`services.php?action=${action}`, { method: 'POST', body: formData });
                const data = await res.json();
                if(data.success) showAlert('Success!', 'Service saved.', 'success', true);
                else showAlert('Error', data.message, 'error');
            } catch(err) { showAlert('Error', 'Request failed.', 'error'); }
        });

        function editService(srv) {
            document.getElementById('service-id').value = srv.id;
            document.getElementById('service-name').value = srv.name;
            document.getElementById('service-price').value = srv.price;
            document.getElementById('service-duration').value = srv.duration;
            document.getElementById('service-desc').value = srv.description;
            document.getElementById('serviceFormTitle').textContent = 'Edit Service';
            document.getElementById('service-btn-text').textContent = 'Update Service';
            document.getElementById('cancelServiceEdit').style.display = 'block';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function resetServiceForm() {
            serviceForm.reset();
            document.getElementById('service-id').value = '';
            document.getElementById('serviceFormTitle').textContent = 'Manage Service';
            document.getElementById('service-btn-text').textContent = 'Save Service';
            document.getElementById('cancelServiceEdit').style.display = 'none';
        }

        // --- EVENT LOGIC ---
        const eventForm = document.getElementById('eventForm');
        eventForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(eventForm);
            try {
                const res = await fetch('manage_events.php', { method: 'POST', body: formData });
                const data = await res.json();
                if(data.success) showAlert('Success!', 'Event saved.', 'success', true);
                else showAlert('Error', 'Error saving event', 'error');
            } catch(err) { showAlert('Error', 'Request failed', 'error'); }
        });

        function editEvent(evt) {
            document.getElementById('event-id').value = evt.id;
            document.getElementById('event-title').value = evt.title;
            document.getElementById('event-date').value = evt.event_date;
            document.getElementById('event-time').value = evt.event_time;
            document.getElementById('event-location').value = evt.location;
            document.getElementById('eventFormTitle').textContent = 'Edit Event';
            document.getElementById('event-btn-text').textContent = 'Update Event';
            document.getElementById('cancelEventEdit').style.display = 'block';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function resetEventForm() {
            eventForm.reset();
            document.getElementById('event-id').value = '';
            document.getElementById('eventFormTitle').textContent = 'Add Event';
            document.getElementById('event-btn-text').textContent = 'Publish Event';
            document.getElementById('cancelEventEdit').style.display = 'none';
        }

        // --- ARTIST LOGIC (SINGLE) ---
        const artistForm = document.getElementById('artistForm');
        artistForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(artistForm);
            try {
                const res = await fetch('manage_artists.php', { method: 'POST', body: formData });
                const data = await res.json();
                if(data.success) showAlert('Success!', 'Profile updated.', 'success', true);
                else showAlert('Error', 'Error updating profile', 'error');
            } catch(err) { showAlert('Error', 'Request failed', 'error'); }
        });
    </script>
</body>
</html>