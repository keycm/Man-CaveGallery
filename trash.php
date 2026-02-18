<?php
session_start();
include 'config.php';

if (!isset($_SESSION['username']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: index.php");
    exit();
}

// --- FILTERING LOGIC ---
$filterSource = $_GET['source'] ?? 'all';
$sortOrder = $_GET['sort'] ?? 'desc';

$whereSQL = "1";
if ($filterSource !== 'all') {
    $sourceEscaped = mysqli_real_escape_string($conn, $filterSource);
    $whereSQL .= " AND source = '$sourceEscaped'";
}

$orderSQL = ($sortOrder === 'asc') ? "ASC" : "DESC";

$trash_items = [];
$sql = "SELECT * FROM trash_bin WHERE $whereSQL ORDER BY deleted_at $orderSQL";
$result = mysqli_query($conn, $sql);
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $trash_items[] = $row;
    }
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
    <title>Recycle Bin | ManCave Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600;700;800&family=Playfair+Display:wght@600;700&family=Pacifico&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="admin_new_style.css">
    
    <style>
        /* === THEME VARIABLES (LIGHT DEFAULT) === */
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
            
            /* Dimensions */
            --sidebar-width: 280px;
            --radius-soft: 12px;
            
            /* Fonts */
            --font-head: 'Playfair Display', serif;
            --font-main: 'Nunito Sans', sans-serif;
            --font-script: 'Pacifico', cursive;
        }

        /* === DARK MODE OVERRIDES === */
        [data-theme="dark"] {
            /* Base Colors */
            --bg-body: #121212;
            --text-main: #e0e0e0;
            --text-muted: #a0a0a0;
            --border-color: rgba(255,255,255,0.1);
            --card-bg: #1e1e1e;
            --shadow-color: rgba(0,0,0,0.3);
            --input-bg: #2a2a2a;

            /* Sidebar Colors */
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
        }

        /* === SIDEBAR DESIGN === */
        .sidebar {
            position: fixed;
            top: 0; left: 0; bottom: 0;
            width: var(--sidebar-width);
            background: var(--sidebar-bg);
            padding: 30px 20px;
            display: flex;
            flex-direction: column;
            border-right: 1px solid var(--border-color);
            box-shadow: 5px 0 25px var(--shadow-color);
            z-index: 1000;
            transition: all 0.3s ease;
        }

        /* Sidebar Logo Area */
        .sidebar-header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .sidebar-logo {
            text-decoration: none;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0;
            line-height: 1;
        }
        
        .logo-top {
            font-family: var(--font-head);
            font-size: 0.85rem; 
            font-weight: 700;
            color: var(--text-muted); 
            letter-spacing: 2px;
            margin-bottom: -5px;
        }

        .logo-main {
            font-family: var(--font-script);
            font-size: 3rem;
            font-weight: 400;
            color: var(--logo-color);
            transform: rotate(-4deg);
            text-shadow: 0 3px 6px rgba(0,0,0,0.15);
            margin: 0;
            padding: 5px 0;
            transition: all 0.4s ease;
        }
        
        .logo-red { color: #ff4d4d; }

        .logo-bottom {
            font-family: var(--font-main);
            font-size: 0.75rem;
            font-weight: 800;
            color: var(--text-muted);
            letter-spacing: 8px;
            text-transform: uppercase;
            margin-top: -2px;
            margin-right: -8px;
        }

        /* Sidebar Navigation */
        .sidebar-nav { flex: 1; overflow-y: auto; }
        .sidebar-nav ul { list-style: none; padding: 0; }
        .sidebar-nav li { margin-bottom: 8px; }

        .sidebar-nav a {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 14px 20px;
            color: var(--sidebar-text);
            text-decoration: none;
            font-weight: 700;
            font-size: 0.95rem;
            border-radius: var(--radius-soft);
            transition: all 0.3s ease;
        }

        .sidebar-nav a i {
            width: 20px;
            text-align: center;
            font-size: 1.1rem;
            opacity: 0.7;
            transition: 0.3s;
        }

        .sidebar-nav a:hover {
            background: var(--sidebar-hover);
            color: var(--accent);
            transform: translateX(3px);
        }
        .sidebar-nav a:hover i { color: var(--accent); opacity: 1; }

        .sidebar-nav li.active a {
            background: var(--sidebar-active-bg);
            color: var(--sidebar-active-text);
            box-shadow: 0 4px 12px rgba(205, 133, 63, 0.3);
        }
        .sidebar-nav li.active a i { color: var(--white); opacity: 1; }

        /* Sidebar Footer */
        .sidebar-footer {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }
        .btn-logout {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 12px;
            background: rgba(255, 77, 77, 0.1);
            color: #ff4d4d;
            border-radius: var(--radius-soft);
            font-weight: 700;
            transition: 0.3s;
            text-decoration: none;
        }
        .btn-logout:hover {
            background: #ff4d4d;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 10px rgba(255, 77, 77, 0.2);
        }

        /* === MAIN CONTENT === */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 30px 40px;
            width: calc(100% - var(--sidebar-width));
        }

        /* === PAGE ELEMENTS === */
        .page-header h1 { color: var(--text-main); font-family: var(--font-head); }
        .page-header p { color: var(--text-muted); }

        /* Controls */
        .controls-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; gap: 15px; flex-wrap: wrap; }
        .filter-form { display: flex; gap: 10px; align-items: center; }
        
        select { 
            padding: 10px 20px; border-radius: 50px; 
            border: 1px solid var(--border-color); 
            background: var(--input-bg); 
            color: var(--text-main); 
            outline: none; cursor: pointer; 
            font-weight: 700; font-size: 0.9rem;
            transition: 0.3s;
        }
        select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(205, 133, 63, 0.1); }

        /* Cards & Tables */
        .card { background: var(--card-bg); border-radius: var(--radius-soft); box-shadow: 0 5px 15px var(--shadow-color); padding: 20px; border: 1px solid var(--border-color); }
        
        .styled-table { width: 100%; border-collapse: collapse; }
        .styled-table th { text-align: left; padding: 15px; color: var(--text-muted); border-bottom: 2px solid var(--border-color); font-weight: 700; }
        .styled-table td { padding: 15px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        .styled-table tr:hover td { background-color: var(--sidebar-hover); }

        /* Source Badges */
        .badge-source { padding: 5px 12px; border-radius: 50px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; display: inline-block; }
        .source-artworks { background: rgba(139, 92, 246, 0.1); color: #8b5cf6; }
        .source-bookings { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
        .source-services { background: rgba(249, 115, 22, 0.1); color: #f97316; }
        .source-users { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .source-events { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        .source-artists { background: rgba(236, 72, 153, 0.1); color: #ec4899; }
        .source-inquiries { background: rgba(107, 114, 128, 0.1); color: #6b7280; }
        .source-ratings { background: rgba(194, 65, 12, 0.1); color: #c2410c; }

        /* Actions */
        .actions { display: flex; gap: 5px; }
        .btn-icon { width: 32px; height: 32px; border-radius: 50%; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: 0.2s; }
        .btn-icon.edit { background: rgba(16, 185, 129, 0.1); color: #10b981; } /* Green for Restore */
        .btn-icon.delete { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .btn-icon:hover { transform: translateY(-2px); }

        /* --- HEADER ACTIONS --- */
        .header-actions { display: flex; align-items: center; gap: 20px; }
        .notif-wrapper { position: relative; }
        .icon-btn { 
            background: var(--card-bg); width: 45px; height: 45px; border-radius: 50%; 
            display: flex; align-items: center; justify-content: center; 
            font-size: 1.2rem; color: var(--text-muted); cursor: pointer; 
            box-shadow: 0 4px 10px var(--shadow-color); border: 1px solid var(--border-color); transition: 0.3s; 
        }
        .icon-btn:hover { color: var(--accent); transform: translateY(-2px); box-shadow: 0 6px 15px rgba(0,0,0,0.1); }
        .notif-bell .dot { position: absolute; top: -2px; right: -2px; background: #ff4d4d; color: white; font-size: 0.65rem; font-weight: 700; border-radius: 50%; min-width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; border: 2px solid var(--card-bg); }
        
        .notif-dropdown { display: none; position: absolute; right: -10px; top: 60px; width: 340px; background: var(--card-bg); border-radius: 16px; box-shadow: 0 15px 50px rgba(0,0,0,0.2); border: 1px solid var(--border-color); z-index: 1100; overflow: hidden; animation: slideDown 0.2s ease-out; }
        .notif-dropdown.active { display: block; }
        .notif-header { padding: 15px 25px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: var(--sidebar-hover); font-weight: 800; font-size: 0.95rem; color: var(--text-main); }
        .notif-item { padding: 15px 35px 15px 25px; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; cursor: pointer; position: relative; color: var(--text-main); }
        .notif-item:hover { background: var(--sidebar-hover); }
        .notif-msg { color: var(--text-main); }
        .notif-time { color: var(--text-muted); }
        .no-notif { padding: 30px; text-align: center; color: var(--text-muted); font-style: italic; }
        .small-btn { border: none; background: none; font-size: 0.75rem; cursor: pointer; font-weight: 700; color: var(--accent); text-transform: uppercase; }
        .btn-notif-close { background: none; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; position: absolute; top:12px; right:12px; }
        
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }

        /* Modals */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: 0.3s; z-index: 2000; }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        .modal-card { background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); }
        
        .modal-card.small { width: 400px; max-width: 90%; padding: 40px 30px; text-align: center; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
        
        .modal-header-icon { width: 70px; height: 70px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
        .delete-icon { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .restore-icon { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        
        .modal-card.small h3 { font-family: var(--font-head); font-size: 1.5rem; margin-bottom: 10px; color: var(--text-main); }
        .modal-card.small p { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 25px; }

        .btn-group { display: flex; gap: 10px; justify-content: center; }
        .btn-friendly { padding: 12px 25px; border-radius: 50px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; font-size: 0.9rem; }
        .btn-friendly:hover { transform: translateY(-2px); opacity: 0.9; }

        @media (max-width: 1024px) {
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
                <li><a href="content.php"><i class="fas fa-layer-group"></i> <span>Website Content</span></a></li>
                <li><a href="manage_hero.php"><i class="fas fa-images"></i> <span>Manage Slider</span></a></li>
                <li><a href="users.php"><i class="fas fa-users"></i> <span>Customers & Staff</span></a></li>
                <li><a href="feedback.php"><i class="fas fa-comments"></i> <span>Message & Feedback</span></a></li>
                <li class="active"><a href="trash.php"><i class="fas fa-trash-alt"></i> <span>Recycle Bin</span></a></li>
            </ul>
        </nav>
        <div class="sidebar-footer">
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Logout</span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="top-bar">
            <div class="page-header">
                <h1>Recycle Bin</h1>
                <p>Restore deleted items or remove them permanently.</p>
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
            <form method="GET" class="filter-form">
                <select name="source" onchange="this.form.submit()">
                    <option value="all" <?= $filterSource == 'all' ? 'selected' : '' ?>>All Sources</option>
                    <option value="artworks" <?= $filterSource == 'artworks' ? 'selected' : '' ?>>Artworks</option>
                    <option value="bookings" <?= $filterSource == 'bookings' ? 'selected' : '' ?>>Bookings</option>
                    <option value="services" <?= $filterSource == 'services' ? 'selected' : '' ?>>Services</option>
                    <option value="events" <?= $filterSource == 'events' ? 'selected' : '' ?>>Events</option>
                    <option value="artists" <?= $filterSource == 'artists' ? 'selected' : '' ?>>Artists</option>
                    <option value="users" <?= $filterSource == 'users' ? 'selected' : '' ?>>Users</option>
                    <option value="inquiries" <?= $filterSource == 'inquiries' ? 'selected' : '' ?>>Inquiries</option>
                    <option value="ratings" <?= $filterSource == 'ratings' ? 'selected' : '' ?>>Ratings</option>
                </select>

                <select name="sort" onchange="this.form.submit()">
                    <option value="desc" <?= $sortOrder == 'desc' ? 'selected' : '' ?>>Newest Deleted</option>
                    <option value="asc" <?= $sortOrder == 'asc' ? 'selected' : '' ?>>Oldest Deleted</option>
                </select>
            </form>
        </div>

        <div class="card table-card">
            <div class="table-responsive">
                <table class="styled-table" id="trashTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Item Details</th>
                            <th>Source</th>
                            <th>Deleted Date</th>
                            <th style="text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($trash_items)): ?>
                            <tr><td colspan="5" class="text-center" style="padding:40px; color:var(--text-muted);">No items found in trash.</td></tr>
                        <?php else: ?>
                            <?php foreach ($trash_items as $item): 
                                $parts = explode('|', $item['item_name'], 2);
                                $displayName = $parts[0];
                                $sourceClass = 'source-' . strtolower($item['source']);
                            ?>
                            <tr>
                                <td><span class="id-badge">#<?= $item['id'] ?></span></td>
                                <td><strong><?= htmlspecialchars($displayName) ?></strong></td>
                                <td><span class="badge-source <?= $sourceClass ?>"><?= ucfirst($item['source']) ?></span></td>
                                <td>
                                    <i class="far fa-clock" style="color:var(--text-muted); margin-right:5px;"></i>
                                    <?= date('M d, Y h:i A', strtotime($item['deleted_at'])) ?>
                                </td>
                                <td style="text-align: right;">
                                    <div class="actions" style="justify-content: flex-end;">
                                        <button class="btn-icon edit" onclick="confirmAction('restore', <?= $item['id'] ?>)" title="Restore Item"><i class="fas fa-undo"></i></button>
                                        <button class="btn-icon delete" onclick="confirmAction('delete', <?= $item['id'] ?>)" title="Delete Permanently"><i class="fas fa-times"></i></button>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <div class="modal-overlay" id="confirmModal">
        <div class="modal-card small">
            <div class="modal-header-icon" id="confirmIcon"></div>
            <h3 id="confirmTitle"></h3>
            <p id="confirmText"></p>
            <div class="btn-group">
                <button class="btn-friendly" style="background:var(--border-color); color:var(--text-main);" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn-friendly" id="confirmBtnAction" style="color:white;"></button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="alertModal">
        <div class="modal-card small">
            <div class="modal-header-icon" id="alertIcon"></div>
            <h3 id="alertTitle"></h3>
            <p id="alertMessage"></p>
            <button class="btn-friendly" style="background:var(--text-main); color:var(--bg-body); width:100%;" onclick="closeModal('alertModal'); location.reload();">Okay</button>
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

            // Notifications
            const notifBtn = document.getElementById('adminNotifBtn');
            const notifDropdown = document.getElementById('adminNotifDropdown');
            const notifBadge = document.getElementById('adminNotifBadge');
            const notifList = document.getElementById('adminNotifList');
            const markAllBtn = document.getElementById('adminMarkAllRead');

            if(notifBtn) {
                notifBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    notifDropdown.classList.toggle('active');
                });

                function fetchNotifications() {
                    fetch('fetch_notifications.php')
                        .then(res => res.json())
                        .then(data => {
                            if (data.status === 'success') {
                                if (data.unread_count > 0) {
                                    notifBadge.innerText = data.unread_count;
                                    notifBadge.style.display = 'flex';
                                } else {
                                    notifBadge.style.display = 'none';
                                }
                                notifList.innerHTML = '';
                                if (data.notifications.length === 0) {
                                    notifList.innerHTML = '<li class="no-notif">No new notifications</li>';
                                } else {
                                    data.notifications.forEach(notif => {
                                        const li = document.createElement('li');
                                        li.className = `notif-item ${notif.is_read == 0 ? 'unread' : ''}`;
                                        li.innerHTML = `
                                            <div class="notif-msg">${notif.message}</div>
                                            <div class="notif-time">${notif.created_at}</div>
                                            <button class="btn-notif-close" title="Delete">×</button>
                                        `;
                                        li.addEventListener('click', (e) => {
                                            if (e.target.classList.contains('btn-notif-close')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('mark_as_read.php', { method: 'POST', body: formData }).then(() => fetchNotifications());
                                        });
                                        li.querySelector('.btn-notif-close').addEventListener('click', (e) => {
                                            e.stopPropagation();
                                            if (!confirm('Delete notification?')) return;
                                            const formData = new FormData();
                                            formData.append('id', notif.id);
                                            fetch('delete_notifications.php', { method: 'POST', body: formData }).then(res => res.json()).then(d => { if (d.status === 'success') fetchNotifications(); });
                                        });
                                        notifList.appendChild(li);
                                    });
                                }
                            }
                        });
                }

                if (markAllBtn) {
                    markAllBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        fetch('mark_all_as_read.php', { method: 'POST' }).then(() => fetchNotifications());
                    });
                }

                window.addEventListener('click', () => {
                    if (notifDropdown.classList.contains('active')) notifDropdown.classList.remove('active');
                });
                notifDropdown.addEventListener('click', (e) => e.stopPropagation());

                fetchNotifications();
                setInterval(fetchNotifications, 30000);
            }
        });

        // --- MODAL LOGIC ---
        let actionCallback = null;

        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        function showAlert(title, msg, type) {
            document.getElementById('alertTitle').innerText = title;
            document.getElementById('alertMessage').innerText = msg;
            
            const icon = document.getElementById('alertIcon');
            if (type === 'success') {
                icon.className = 'modal-header-icon restore-icon';
                icon.innerHTML = '<i class="fas fa-check"></i>';
            } else {
                icon.className = 'modal-header-icon delete-icon';
                icon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            }
            
            document.getElementById('alertModal').classList.add('active');
        }

        function confirmAction(type, id) {
            const icon = document.getElementById('confirmIcon');
            const btn = document.getElementById('confirmBtnAction');
            
            if (type === 'restore') {
                document.getElementById('confirmTitle').innerText = 'Restore Item?';
                document.getElementById('confirmText').innerText = 'This item will be moved back to its original location.';
                icon.className = 'modal-header-icon restore-icon';
                icon.innerHTML = '<i class="fas fa-undo"></i>';
                btn.style.background = '#10b981';
                btn.innerText = 'Restore';
                actionCallback = () => performRestore(id);
            } else {
                document.getElementById('confirmTitle').innerText = 'Delete Permanently?';
                document.getElementById('confirmText').innerText = 'This action cannot be undone. Are you sure?';
                icon.className = 'modal-header-icon delete-icon';
                icon.innerHTML = '<i class="fas fa-trash-alt"></i>';
                btn.style.background = '#ef4444';
                btn.innerText = 'Delete';
                actionCallback = () => performDelete(id);
            }
            
            document.getElementById('confirmModal').classList.add('active');
        }

        document.getElementById('confirmBtnAction').addEventListener('click', () => {
            if (actionCallback) actionCallback();
            closeModal('confirmModal');
        });

        // --- API CALLS ---
        async function performRestore(id) {
            const formData = new FormData();
            formData.append('id', id);
            formData.append('action', 'restore');
            try {
                const res = await fetch('restore_item.php', { method: 'POST', body: formData });
                const data = await res.json();
                if(data.status === 'success') showAlert('Restored!', 'Item restored successfully.', 'success');
                else showAlert('Error', data.message, 'error');
            } catch (err) { showAlert('Error', 'An unexpected error occurred.', 'error'); }
        }

        async function performDelete(id) {
            const formData = new FormData();
            formData.append('id', id);
            formData.append('action', 'permanent_delete');
            try {
                const res = await fetch('restore_item.php', { method: 'POST', body: formData });
                const data = await res.json();
                if(data.status === 'success') showAlert('Deleted!', 'Item deleted permanently.', 'success');
                else showAlert('Error', data.message, 'error');
            } catch (err) { showAlert('Error', 'An unexpected error occurred.', 'error'); }
        }
    </script>
</body>
</html>