--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: Content Group Process Client Mapping
version: 19
description: Group of Process Name to Client App detectors.
bundle_description: $VAR1 = {
          'Dashlane' => 'Offers a password manager and digital wallet.',
          'QQ' => 'Chinese instant messaging software.',
          'KakaoTalk' => 'Mobile messaging for smartphones.',
          'PHP' => 'Scripting language for developing server based web applications.',
          'DDM' => 'IBM Lotus Domino domain monitoring, a management system for Domino networks.',
          'WinZip' => 'Provides a file compression utility.',
          'MagentaCloud' => 'Provides cloud storage service.',
          'Daum' => 'Popular South Korean web portal.',
          'Kaspersky' => 'Kaspersky Antivirus/Security software download and updates.',
          'Windows Media Player' => 'Microsoft application that plays files and streams, both audio and video.',
          'Flow' => 'Project and task management application.',
          'Redbooth' => 'Provides a communication and collaboration platform that facilitates task and file sharing, discussions, and more.',
          'iCloud' => 'Apple cloud storage service.',
          'Logitech' => 'Company develops Computer peripherals and accessories.',
          'SVN' => 'Managing Subversion servers.',
          'TripIt' => 'Cloud based travel planner.',
          'Signal' => 'Signal is a cross-platform centralized encrypted messaging service developed by the Signal Technology Foundation and Signal Messenger LLC.',
          'DLS' => 'Directory Location Service, registered with IANA on port 197 tcp/udp.',
          'Tableau' => 'Tableau Software is an interactive data visualization and data analytics software which provides pictorial and graphical representations of data.',
          'Pandora' => 'Audio streaming.',
          'Aliwangwang' => 'Instant messaging.',
          'Thousand Eyes' => 'Software that performances of network.',
          'Youdao Dictionary' => 'A chinese dictionary, available online and offline.',
          'ChatGPT' => 'An AI which is trained to follow an instruction in a prompt and provide a detailed response.',
          'Proton VPN' => 'VPN/anonymizer app.',
          'Quake' => 'First person shooter.',
          'Chrome' => 'Google\'s web browser.',
          'Township' => 'Offers a city building and farming game.',
          'Tabnine' => 'Code assistant plugin for major IDEs.',
          'WhatsApp' => 'A cross-platform mobile messaging app which serves as a free alternative to SMS messages.',
          'Calendly' => 'Calendar and group scheduling software application.',
          'Docker' => 'Enables development and IT operations teams to securely build, share and run any application, anywhere.',
          'Amazon Web Services' => 'Online cloud computing service.',
          'iAd' => 'Web advertisement services.',
          'Monitor' => 'Registered with IANA on port 561 TCP/UDP.',
          'Time' => 'A network protocol in the Internet Protocol Suite defined in 1983 in RFC 868. Its purpose is to provide a site-independent, machine readable date and time.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Apple Music' => 'Internet radio by Apple.',
          'Hola' => 'An open source VPN.',
          'OCSPD' => 'Framework for Online certificate validation.',
          'Instapaper' => 'App to save wb pages for later use.',
          'VidyoConnect' => 'Delivers desktop video conferencing for group meeting collaboration.',
          'Western Digital' => 'Data storage company and hard disk drive manufacturers.',
          'Wickr' => 'Provides  a mobile communication application that provides military-grade encryption of text, picture, audio, and video messages.',
          'Webshots' => 'Service for uploading and sharing photos and videos.',
          'Windscribe' => 'VPN traffic generated by Windscribe.',
          'Mendeley' => 'A tool for sharing, storing, and organizing reference material such as PDFs.',
          'Roblox' => 'Online gaming platform.',
          'DotVPN' => 'A VPN Tunneling app.',
          'Zeplin' => 'Provides collaboration tool for UI designers and front end developers.',
          'Figma' => 'Provides collaboration interface design tool.',
          'Plex TV' => 'Allows users to stream their own media from one device to others over the Plex TV network.',
          '1Password' => 'Password management application.',
          'Screenleap' => 'Provides screen sharing and meeting software.',
          'MongoDB' => 'Source-available cross-platform document-oriented database program.',
          'Termius' => 'SSH client.',
          'RealVNC' => 'A VNC package that supports client and server side, and also provides cloud-based services such as chat and file transfer.',
          'DuckDuckGo' => 'Search engine.',
          'Autodesk' => 'A CAD and 3D printing software company.',
          'Netease' => 'Chinese web portal.',
          'Twitter' => 'Social networking and microblogging site.',
          'Tesla' => 'Sustainable energy services for a world powered by solar energy, running on batteries and transported by electric vehicles.',
          'Kugou' => 'Peer-to-peer music.',
          'TOR' => 'The Onion Router. A client which allows a user to send and relay internet traffic anonymously.',
          'Google Drive' => 'A free office suite and cloud storage system hosted by Google.',
          'Hotspot Shield' => 'Anonymizer and tunnel that encrypts communications.',
          'SurfShark' => 'VPN/anonymizer app.',
          'Psiphon' => 'Web proxy/anonymizer.',
          'Baidu' => 'Chinese Search engine.',
          'cURL' => 'Utility for HTTP access.',
          'NordVPN' => 'NordVPN is a VPN service provided by company Nordsec Ltd.',
          'Autopilot' => 'Provides marketing automation software helps to capture leads and data from any websites to organize and target marketing using lists, segments and folders.',
          'Private Internet Access' => 'Provides virtual private network services.',
          'Java' => 'Java based application.',
          'Ultrasurf' => 'Freeware anti-censorship proxy.',
          'Todoist' => 'Task management solution.',
          'Google Analytics' => 'Google service that tracks and generates detailed web statistics.',
          'Cisco Secure Endpoint' => 'Cloud-based real time antivirus protection. (AMP for Endpoints).',
          'BitTorrent' => 'A peer-to-peer file sharing protocol used for transferring large amounts of data.',
          'Snapchat' => 'Online photo sharing.',
          'CloudMounter' => 'Offers tool for mounting cloud storage as local disk on laptops and Pcs.',
          'Synergy' => 'Lets users a mouse and keyboard between multiple computers.',
          'ProtonMail' => 'Provides a secure email services.',
          'Sync.com' => 'Offers cloud storage.',
          'RingCentral' => 'RingCentral is an American publicly traded provider of cloud-based communications and collaboration solutions for businesses.',
          'Synology DSM' => 'Synology is a Network Attached Storage (NAS) appliances running Synology\'s DSM Software.',
          'Nessus' => 'Active network scanner.',
          'Zalo' => 'Free messaging and calling application.',
          'Ivacy Login' => 'Logging into Ivacy VPN, a firewall-bypassing service.',
          'PDF Expert' => 'App for iPad to view and endit PDF files.',
          'Jira' => 'Web based bug tracking and project management tool.',
          'Battle.net' => 'Game networking service.',
          'Kodi' => 'Open source media player.',
          'Adobe Connect' => 'Online meeting and collaboration system.',
          'Miro' => 'Offers Online whiteboard and real-time team collaboration software for teams.',
          'MagicJack' => 'Magic Jack is a USB device that allows any phone to make free calls within the US and Canada.',
          'YY' => 'Chinese Chat application.',
          'New Relic' => 'Web metrics site.',
          'AnyDesk' => 'Remote Desktop Access Software.',
          'BlueJeans' => 'An interoperable cloud-based video conferencing service.',
          'Minecraft' => 'Online game.',
          'WeChat' => 'Mobile text and voice messaging application.',
          'Mobile Safari' => 'Apple web browser for mobile devices.',
          'LiveAgent' => 'Provides live chat and helpdesk software.',
          'Ccleaner Cloud' => 'Provides pc cleaning and monitoring software.',
          'Eclipse' => 'Software Updates for Eclipse.',
          'GoodSync' => 'File transfer and synchronization service.',
          'Steam' => 'Massive gaming and communications platform.',
          'Upwork' => 'Global freelancing platform for businesses and independent professionals be connected.',
          'Monster VPN' => 'Monster VPN is a free VPN proxy, to get connected quickly to unblock sites, WiFi hotspot secure and protect privacy.',
          'WebEx' => 'Cisco\'s online meeting and web conferencing application.',
          'Gyazo Teams' => 'Allows users to create screenshots and share with the team.',
          'Libwww-Perl' => 'Library for World wide web service.',
          'Potato VPN' => 'PotatoVPN is a cross-platform VPN application created by FASTPOTATO PTE LTD.',
          'Mutt' => 'An email client.',
          'Prezi' => 'Presentation tool.',
          'Basecamp' => 'Web based project management tool.',
          'Pcloud' => 'Provides online storage service.',
          'Kaspersky Network Agent' => 'Kaspersky Network Agent facilitates interaction between the Administration server and Kaspersky lab products.',
          'WeChat update' => 'WeChat software update.',
          'CyberGhost VPN' => 'An anonymizer that obfuscates web usage.',
          'WinSCP' => 'A free SFTP and FTP client for Windows.',
          'Asus' => 'Manufacturer of PCs and PC components.',
          'VyprVPN Login' => 'Logins to VyprVPN, a personal VPN service.',
          'TradingView' => 'Provides a cloud-based charting, financial visualization and social networking platform for traders and investors.',
          'Jisupdf' => 'Provides online PDF editor, converter and PDF app on mobile and desktop.',
          'Lenovo' => 'Company manufactures/markets computers, software and related services.',
          'Spotify' => 'Social Music Player.',
          'Draw.io' => 'Online diagram and flowchart application.',
          'Xcode' => 'Apple\'s IDE.',
          'MobaXterm' => 'Xserver and tabbed SSH client for Windows.',
          'MelOn' => 'Korean music site.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'Notion' => 'Project management and note-taking software platform.',
          'Yandex' => 'Russian search engine.',
          'Skype' => 'A software application that allows users to chat, make voice/video calls, and transfer files over the Internet.',
          'Screencast-O-Matic' => 'Used to create and share screen recordings.',
          'McAfee' => 'McAfee Antivirus/Security software download and updates.',
          'Remote Desktop Manager' => 'Provides remote connection and password management software.',
          'TuneIn' => 'Online Radio station.',
          'Office 365' => 'Traffic generated by MS Office 365 applications and web services.',
          'CloudFlare' => 'Advertisement site.',
          'Monday' => 'Offers a team management solution.',
          'Babylon' => 'Search engine, Translation and Dictionary toolbar.',
          'Pocket' => 'App to save web pages.',
          'Epic Games' => 'Operates as a video game development company.',
          'JetBrains' => 'A collection of IDEs for different programming languages and frameworks.',
          'Telegram' => 'Telegram is a messaging app with a focus on speed and security.',
          'Airtable' => 'Airtable is a collaboration software which provides a way to create your own organizational databases.',
          'Prime Video' => 'Amazon video streaming site.',
          'Maxthon' => 'Develops web browsers that give users browsing experience across multiple platforms.',
          'Webex Teams' => 'Webex Teams is a collaboration tool with various clients (Windows, OS X, Android, Windows Mobile, iPad, iPhone, Web) for messages, calls, meetings, etc.',
          'Evony' => 'Browser-based online multiplayer game.',
          'Honey' => 'Digital tool to find the best savings, perks, and all around value, coupons and discounts.',
          'StrongVPN' => 'VPN/anonymizer app.',
          'Hide My Ass!' => 'Web surfing anonymizer.',
          'World of Warcraft' => 'Massively multiplayer online role-playing game.',
          'Vuze' => 'Java based BitTorrent client.',
          'Toggl Track' => 'Offers an online time tracking software.',
          'PaleMoon' => 'A web browser.',
          'Facebook' => 'Facebook is a social networking service.',
          'Viber' => 'Smartphone app that allows for free phone calls and text messages.',
          'MySQL' => 'A relational database management system (RDBMS) that runs as a server providing multi-user access to a number of databases.',
          'iPass' => 'Cloud based communication service provider.',
          'Grammarly' => 'Digital writing tool using artificial intelligence and natural language processing (auto corecting tool).',
          'Box' => 'File storage and transfer site.',
          'Zoho Mail' => 'Zoho webmail.',
          'Wow' => 'A search engine.',
          'Nmap' => 'Network Mapper, a security scanner.',
          'Internet Explorer' => 'A Microsoft web browser.',
          'StarCraft II' => 'Provides an online strategy game.',
          'rlogin' => 'Unix utility that allows remote administration from one computer to another.',
          'TeamViewer' => 'Remote desktop control and file transfer software.',
          'Meter' => 'Registered with IANA on port 570 TCP/UDP.',
          'Zscaler' => 'Cloud-based information security.',
          'Grafana' => 'Multi-platform open source analytics and interactive visualization web application.',
          'Zoho Docs' => 'Online document management software that lets you manage and store all your files on the cloud.',
          'Garmin' => 'Offcial website for Garmin, GPS manufacturer.',
          'Thunderbird' => 'Mozilla email client.',
          'Opera' => 'A web browser.',
          'CloudApp' => 'Data synch and collaboration app.',
          'RealPlayer Cloud' => 'RealNetworks cloud player.',
          'Panda' => 'Panda Security Antivirus/Security software download and updates.',
          'Yandex Disk' => 'A Yandex cloud storage product.',
          'Walkme' => 'Software-as-a-service company that helps users navigate the features of other web-based services.',
          'Pokerstars' => 'Offers an online poker cardroom where users can play many variations of Poker.',
          'Trillian' => 'Provides instant messaging service business.',
          'GoToMeeting' => 'Online meeting and desktop sharing service.',
          'YouTube' => 'A video-sharing website on which users can upload, share, and view videos.',
          'Ninite' => 'A tool that manages installation and upgrading of apps.',
          'Discord' => 'VoIP, instant messaging and digital distribution platform designed for creating communities.',
          'Apple Developer' => 'Web portal for Apple Developer.',
          'NetNewsWire' => 'News feed and aggregator for iOS.',
          'HearthStone' => 'Online digital collectible card game.',
          'Wget' => 'Application that allows HTTP access.',
          'BoxCryptor' => 'File Encryption software.',
          'Feedly' => 'News Aggregator.',
          'Groove' => 'Microsoft desktop application designed for document collaboration.',
          'iBooks' => 'Mobile app for download and read e-books.',
          'iTop VPN' => 'VPN/anonymizer app.',
          'Ngrok' => 'Multiplatform tunnelling, reverse proxy software.',
          'Deezer' => 'Music streaming service based in Paris.',
          '2048 Game' => 'Online game.',
          'Zoom' => 'Remote conferencing via cloud computing.',
          'Youku' => 'Chinese video hosting and sharing service.',
          'AnyConnect' => 'Cisco VPN server.',
          'League of Legends' => 'Offers an online battle arena video game.',
          'Splunk' => 'System log aggregator.',
          'Smallpdf' => 'Site to compress, merge, split, unlock and convert PDF files for free.',
          'BAND' => 'Provides group communication app.',
          'Anghami' => 'Music streaming site.',
          'Loom' => 'Provides video messaging platform for work.',
          'Apple Update' => 'Apple software updating tool.',
          'Linphone' => 'VoIP application using SIP.',
          'Jabra' => 'Brand specializing in audio equipment and videoconference systems.',
          'TurboTax' => 'Intuit tax preparation software.',
          'CactusVPN' => 'A VPN client.',
          'Gmail' => 'Google online email.',
          'Trend Micro' => 'Security software company.',
          'Norton AntiVirus' => 'Antivirus for PC.',
          'SketchUp' => 'Provides a 3D modeling software.',
          'MinIO' => 'Provides object storage server,for large scale data infrastructure.',
          'iCloud Private Relay' => 'iCloud Private Relay is an iCloud+ service that prevents networks and servers from monitoring a person\'s activity across the internet.',
          'Postman' => 'API platform for developers to design, build, test and iterate their APIs.',
          'Winamp' => 'Media player for Windows PCs.',
          'Letterpress' => 'Word game for iOS.',
          'PTP' => 'Performance Transparency Protocol.',
          'TurboVPN' => 'A VPN client on mobile devices.',
          'Canva' => 'Graphic design software.',
          'Code42' => 'Enterprise data management and security software.',
          'Asana' => 'Collboration service.',
          'SmartDraw' => 'Provides a diagram tool used to make flowcharts, organization charts, mind maps, project charts, and other business visuals.',
          'Microsoft Visual Studio' => 'Microsoft Integrated Developer Environment and toolchain designed to make it easier to develop software for Microsoft platforms.',
          'LastPass' => 'Password management application.',
          'DOTA 2' => 'Operates as a multiplayer online battle arena video game.',
          'Sogou' => 'Chinese web portal.',
          'Firefox' => 'A mozilla web browser.',
          'ExpressVPN' => 'A paid VPN platform with desktop and mobile apps.',
          'Bria' => 'VoIP based software for video calls and instant messaging.',
          'Apple News' => 'Apple News is an app the brings news and magazines, all in one place.',
          'VPN Unlimited' => 'Provides virtual private network services.',
          'Wrike' => 'Project management software.',
          'Amazon Cloud Player' => 'Media player by Amazon facilitates listening music from cloud or download on the device.',
          'BitComet' => 'BitTorrent client.',
          'LightShot' => 'Provides a screen capture tool for Mac and Windows.',
          'Shazam' => 'Media Playing and sharing application.',
          'Epic Games\' Fortnite' => 'Offers co-op sandbox survival game.',
          'Free Conference Call' => 'Offers a service for virtual meetings.',
          'Nordlocker' => 'Provides secure storage service.',
          'DeepL Translator' => 'Translation service.',
          'Nvidia' => 'Video chipset manufacturer.',
          'Flipkart' => 'India-based shopping site.',
          'Syncthing' => 'Provides open source peer to peer file synchronization application.',
          'Instagram' => 'Mobile phone photo sharing.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.',
          'Avira Download/Update' => 'Avira Antivirus/Security software download and updates.',
          'Power BI' => 'Power BI is a business analytics service by Microsoft which aims to provide interactive visualizations and business intelligence capabilities.',
          'iLovePDF' => 'Online tools to merge PDF and split PDF files.',
          'Syncplicity' => 'Data synch service.',
          'Smartsheet' => 'Smartsheet is a platform for organizational achievement.',
          'BlueStacks' => 'An app player that runs mobile apps on laptops and desktop machines.',
          'Chat' => 'Registered with IANA on port 531 TCP/UDP.',
          'Tanium' => 'Endpoint security and systems management software.',
          'Microsoft Teams' => 'Microsoft Teams is a unified communication and collaboration platform for workplace communication exchange.',
          'Resilio Sync' => 'Syncs files and folders across devices. Formerly BitTorrent Sync.',
          'Amazon Chime' => 'Offers a video conferencing and communications service for business.',
          'XMind' => 'Provides mind mapping software.',
          'Facetime' => 'Apple video conferencing software.',
          'LINE' => 'Mobile and Desktop App for Instant Messaging.',
          'wink' => 'Offers gaming platform for the users under the local law regulations.',
          'Quicken' => 'Intuit personal finance software.',
          'Evernote' => 'Synched note taking and web bookmarking app.',
          'Avira Phantom VPN' => 'VPN/anonymizer app.',
          'Gtarcade' => 'Provides online games.',
          'ADrive' => 'Online file storage and backup.',
          'SSH' => 'Secure Shell is a network protocol that allows data to be exchanged using a secure channel between two networked devices.',
          'OpenDNS' => 'DNS service for reliability and security for internet surfers.',
          'Mathworks' => 'Producers of MATLAB and other tools for science and engineering.',
          'Apple TV' => 'Apple device to receive the media traffics from Internet or Local networks.',
          'Duo Security' => 'A user-centric access security platform that provides two-factor authentication, endpoint security, remote access solutions and a subsidiary of Cisco.',
          'Zoho Chat' => 'A web-enabled group chat application.',
          'RaiDrive' => 'Operates as a network drive to manage remote files.',
          'WeatherBug' => 'Windows weather application.',
          'Avast' => 'Anti-virus software for Windows PCs.',
          'TunnelBear' => 'An anonymization service.',
          'Airbnb' => 'Online accommodation rental service.',
          'Wireguard' => 'WireGuard is a free and open-source software application and communication protocol that implements virtual private network techniques to create secure point-to-point connections in routed or bridged configurations.',
          'Google Earth' => 'Google\'s virtual globe, map and geographical information program.',
          'Python urllib' => 'Python library for opening URLs.',
          'Dropbox' => 'Cloud based file storage.',
          'Cyberduck' => 'Provides a libre server and cloud storage browser for Mac and Windows.',
          'Flash Video' => 'Multimedia file format and Streaming video using Adobe Flash plugin.',
          'Fitbit' => 'Offers compact, wireless, wearable sensors that track daily activities.',
          'Keyshot' => 'Provides 3D rendering workflow to create visuals.',
          'Evolution' => 'Gnome email client.',
          'GitHub' => 'Code management portal for open Source projects.',
          'Slides' => 'Provides a platform for creating, presenting and sharing presentations.',
          'RescueTime' => 'Provides service that shows how a person spends time and provides tools to help you be more productive.',
          'TimeCamp' => 'Offers a time tracking platform.',
          'Disney Plus' => 'Disney+ is a video on-demand streaming subscription.',
          'WPS Office' => 'Mobile app for viewing and editing documents, spreadsheet and PPTs.',
          'Cato Networks' => 'Company that provides remote access and VPN.',
          'Pulse Secure' => 'Provides zero trust remote access VPN.',
          'RDP' => 'Remote Desktop Protocol provides users with a graphical interface to another computer.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_process_client",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gProcessClientList = {
    --ADrive
    {17, "adrive", 90},
    --Apple Update
    {32, "softwareupdatenotificationmanage", 90},
    --Avira Download/Update
    {45, "avira updater", 90},
    --BitTorrent
    {61, "bittorrent", 90},
    --DLS
    {121, "dls", 90},
    --Dropbox
    {125, "dropbox", 90},
    --Flickr
    {159, "flickr", 90},
    --Google Drive
    {180, "google drive", 90},
    --GoToMeeting
    {187, "go to meeting", 90},
    --Kaspersky
    {248, "avp", 90},
    --Kugou
    {256, "kugou", 90},
    --MagicJack
    {274, "magicjack", 90},
    --McAfee
    {280, "mcafee", 90},
    --Panda
    {359, "panda", 90},
    --QQ
    {386, "qq", 90},
    --rlogin
    {398, "rlogin", 90},
    --Time
    {470, "time", 90},
    --TOR
    {473, "tor", 90},
    --Vuze
    {497, "vuze", 90},
    --World of Warcraft
    {507, "world of warcraft", 90},
    --Zoho Chat
    {529, "zohopingagent", 90},
    --Zoho Mail
    {530, "zoho mail - desktop", 90},
    --Basecamp
    {563, "basecamp", 90},
    --Battle.net
    {564, "battle.net", 90},
    --Chrome
    {589, "chromium", 90},
    --cURL
    {596, "curl", 90},
    --Evolution
    {626, "evolution", 90},
    --Facebook
    {629, "facebook", 90},
    --Firefox
    {638, "firefox", 70},
    --Flash Video
    {639, "flashplayerfeedbackservice", 90},
    --Gmail
    {655, "gmail", 90},
    --Google Analytics
    {660, "ga_service", 90},
    --Google Earth
    {672, "google earth", 90},
    --Internet Explorer
    {686, "explorer", 90},
    --Jira
    {695, "jira", 90},
    --Mobile Safari
    {736, "mobilesafari", 90},
    --Mutt
    {746, "mutt", 90},
    --MySQL
    {747, "mysql", 90},
    --Nessus
    {752, "nessus", 90},
    --Pandora
    {779, "pandora", 90},
    --Quake
    {795, "quake", 90},
    --RDP
    {803, "microsoft remote desktop", 90},
    --Skype
    {832, "skype", 90},
    --SSH
    {846, "ssh", 90},
    --Thunderbird
    {866, "thunderbird", 90},
    --Twitter
    {882, "twitter", 90},
    --WebEx
    {905, "cisco webex", 90},
    --Wget
    {909, "wget", 90},
    --Windows Media Player
    {912, "wmplayer", 90},
    --YouTube
    {929, "youtube", 90},
    --Cisco Secure Endpoint
    {934, "cisco secure endpoint", 90},
    {934, "cisco amp for endpoints", 90},
    --TeamViewer
    {958, "teamviewer_service", 90},
    {958, "team viewer", 90},
    --Daum
    {964, "daumdic", 90},
    --Deezer
    {965, "deezer", 90},
    --Evony
    {970, "evony", 90},
    --Webshots
    {1021, "webshots", 90},
    --Youku
    {1033, "youku", 90},
    --Steam
    {1086, "steam", 90},
    --Winamp
    {1092, "winamp", 90},
    --Adobe Connect
    {1124, "connect", 90},
    --Hotspot Shield
    {1140, "hotspot shield", 90},
    --WhatsApp
    {1143, "whatsapp", 90},
    --Spotify
    {1158, "spotify", 90},
    --Facetime
    {1186, "facetime", 90},
    --iCloud
    {1187, "icloud", 90},
    --Netease
    {1222, "neteasemusic", 90},
    --Instagram
    {1233, "instagram", 90},
    --Avast
    {1264, "avast", 90},
    --Evernote
    {1267, "evernote", 90},
    --Opera
    {1288, "opera installer", 90},
    {1288, "operasetup", 90},
    {1288, "operasetup (1)", 90},
    {1288, "opera_crashreporter", 90},
    --iAd
    {1319, "iad", 90},
    --Box
    {1326, "box", 90},
    --Baidu
    {1345, "baidu", 90},
    --Babylon
    {1346, "babylon", 90},
    --TweetDeck
    {1360, "tweetdeck", 90},
    --Amazon Web Services
    {1392, "aws", 90},
    --KakaoTalk
    {1405, "kakaotalk", 90},
    --Eclipse
    {1413, "eclipse", 90},
    --WeatherBug
    {1421, "weatherbug", 90},
    --Libwww-Perl
    {1430, "perl", 90},
    --Norton AntiVirus
    {1431, "norton antivirus", 90},
    --PaleMoon
    {1592, "palemoon", 90},
    --Apple Developer
    {1596, "testflightserviceextension", 90},
    --Xcode
    {1602, "xcode", 90},
    --Bria
    {1604, "bria", 90},
    --Linphone
    {1606, "linphone", 90},
    --Yandex
    {1616, "yandex", 90},
    --Snapchat
    {1653, "snapchat", 90},
    --Airbnb
    {1655, "airbnb", 90},
    --YY
    {1663, "yy", 90},
    --LINE
    {1667, "line", 90},
    --GitHub
    {1670, "git", 90},
    --Trend Micro
    {1671, "trend micro antivirus", 90},
    --Apple TV
    {1683, "appletv", 90},
    {1683, "tv", 90},
    --Java
    {1692, "java", 90},
    --Feedly
    {1799, "feedly", 90},
    --Minecraft
    {1802, "minecraft", 90},
    --TuneIn
    {1810, "tunein", 90},
    --Splunk
    {2037, "splunk", 90},
    --Prezi
    {2040, "prezi", 90},
    --Letterpress
    {2091, "letterpress", 90},
    --Speedtest
    {2103, "speedtest", 90},
    --Asus
    {2145, "asuswsservice", 90},
    --Nvidia
    {2150, "nvidia telemetry", 90},
    --OCSPD
    {2217, "ocspd", 90},
    --PHP
    {2230, "php", 90},
    --PDF Expert
    {2307, "pdf expert", 90},
    --NetNewsWire
    {2324, "netnewswire", 90},
    --Viber
    {2367, "viber", 90},
    --Sogou
    {2383, "sogoucloud", 90},
    --Pocket
    {2431, "pocket", 90},
    --Instapaper
    {2434, "instapaper", 90},
    --CloudFlare
    {2535, "cloudflare", 90},
    --Aliwangwang
    {2617, "aliwangwang", 90},
    --WeChat
    {2618, "wechat", 90},
    --WeChat update
    {2623, "wechatupdate", 90},
    --Ultrasurf
    {2634, "ultrasurf", 90},
    --VyprVPN Login
    {2644, "vypr vpn", 90},
    --Ivacy Login
    {2646, "ivacy vpn", 90},
    --Hide My Ass!
    {2648, "hide my ass vpn", 90},
    --Resilio Sync
    {2667, "resilio sync", 90},
    --Apple Music
    {2669, "applemusic", 90},
    --Python urllib
    {2685, "python", 90},
    --Mathworks
    {2687, "matlab", 90},
    --GoodSync
    {2688, "goodsync server", 90},
    --New Relic
    {2690, "newrelic", 90},
    --OpenDNS
    {2704, "cisco umbrella", 90},
    --RealPlayer Cloud
    {2718, "realplay", 90},
    --iBooks
    {2724, "books", 90},
    --Garmin
    {2729, "garmin express", 90},
    --Kodi
    {2758, "kodi", 90},
    --Amazon Cloud Player
    {2781, "amazon music", 90},
    --DuckDuckGo
    {2805, "duckduckgo", 90},
    --Office 365
    {2812, "microsoft office", 90},
    --SVN
    {2887, "svn", 90},
    --AnyConnect
    {2921, "cisco anyconnect", 90},
    --Chat
    {3049, "chat", 90},
    --Synergy
    {3063, "synergy", 90},
    --DDM
    {3109, "ddm", 90},
    --Groove
    {3139, "groove", 90},
    --Meter
    {3214, "meter", 90},
    --Monitor
    {3228, "monitor", 90},
    --Nmap
    {3248, "nmap", 90},
    --PTP
    {3623, "ptp", 90},
    --CyberGhost VPN
    {3653, "cyberghost vpn", 90},
    --MelOn
    {3659, "melon", 90},
    --Mendeley
    {3785, "mendeley", 90},
    --Prime Video
    {3793, "prime video", 90},
    --TunnelBear
    {3857, "tunnelbear", 90},
    --Code42
    {3877, "code42 crashplan", 90},
    --Autodesk
    {3888, "autodesk fusion", 90},
    --Wow
    {3910, "wow", 90},
    --Quicken
    {3937, "quicken", 90},
    --TurboTax
    {3938, "turbotax", 90},
    --Asana
    {3950, "asana", 90},
    --Draw.io
    {3956, "draw.io", 90},
    --TripIt
    {3965, "tripit", 90},
    --Flipkart
    {3970, "flipkart", 90},
    --Microsoft Visual Studio
    {3979, "microsoft visual studio", 90},
    --BlueStacks
    {3980, "bluestacks", 90},
    --JetBrains
    {3981, "jetbrains", 90},
    --Youdao Dictionary
    {3982, "youdaodict", 90},
    --WPS Office
    {4010, "wpsoffice", 90},
    --CloudApp
    {4021, "cloudapp", 90},
    --Syncplicity
    {4027, "syncplicity", 90},
    --Ninite
    {4035, "ninite", 90},
    --Western Digital
    {4039, "western digital", 90},
    --Hola
    {4041, "hola", 90},
    --Yandex Disk
    {4049, "yandex disk", 90},
    --Psiphon
    {4075, "psiphon", 90},
    --Tanium
    {4076, "tanium", 90},
    --Webex Teams
    {4080, "teamctl", 90},
    --DotVPN
    {4082, "dot vpn", 90},
    --Synology DSM
    {4089, "synology active backup for busin", 90},
    {4089, "synology cloud drive", 90},
    {4089, "synology surveillance station cl", 90},
    --Anghami
    {4103, "anghami", 90},
    --Telegram
    {4116, "telegram", 90},
    --Ngrok
    {4134, "ngrok", 90},
    --Shazam
    {4138, "shazam", 90},
    --CactusVPN
    {4139, "cactus vpn", 90},
    --TurboVPN
    {4140, "turbo vpn", 90},
    --RealVNC
    {4142, "vncviewer", 90},
    --AnyDesk
    {4145, "anydesk", 90},
    --BlueJeans
    {4151, "bluejeans", 90},
    --LastPass
    {4155, "lastpass", 90},
    --Roblox
    {4193, "roblox", 90},
    --Canva
    {4250, "canva", 90},
    --Upwork
    {4358, "upwork", 90},
    --Zoom
    {4513, "zoom", 90},
    --ExpressVPN
    {4519, "expressvpn", 90},
    --Power BI
    {4520, "power bi", 90},
    --Plex TV
    {4524, "plex", 90},
    --Windscribe
    {4541, "windscribe", 90},
    --Zoho Docs
    {4549, "notebook", 90},
    --BitComet
    {4552, "bitcomet", 90},
    --Kaspersky Network Agent
    {4558, "ksde", 90},
    --Zscaler
    {4592, "zscaler tunnel", 90},
    --Grammarly
    {4598, "grammarly", 90},
    --Honey
    {4599, "honey coupons", 90},
    --Walkme
    {4600, "walkme platform", 90},
    --Microsoft Teams
    {4616, "msteams", 90},
    --Disney Plus
    {4617, "disneyplus", 90},
    --Monster VPN
    {4618, "monster vpn", 90},
    --Smartsheet
    {4621, "smartsheet", 90},
    --Apple News
    {4623, "apple news", 90},
    --RingCentral
    {4635, "ringcentral", 90},
    --Tableau
    {4636, "tableau", 90},
    --Signal
    {4643, "signal", 90},
    --MongoDB
    {4644, "mongodb", 90},
    --Duo Security
    {4648, "duo", 90},
    --Discord
    {4654, "discord", 90},
    --iCloud Private Relay
    {4655, "icloud private relay", 90},
    --WinSCP
    {4658, "winscp", 90},
    --MobaXterm
    {4659, "mobaxterm", 90},
    --Zalo
    {4662, "zalo", 90},
    --Wireguard
    {4663, "wireguard", 90},
    --Thousand Eyes
    {4670, "thousand eyes agent", 90},
    --Logitech
    {4671, "logitech", 90},
    {4671, "logitune", 90},
    --Lenovo
    {4672, "lenovo telemetry", 90},
    {4672, "lenovovantage-(genericmessaginga", 90},
    --iPass
    {4673, "ipass", 90},
    --Proton VPN
    {4903, "proton vpn", 90},
    --SurfShark
    {4904, "surfshark", 90},
    --StrongVPN
    {4906, "strongvpn", 90},
    --NordVPN
    {4907, "nordvpn", 90},
    --Cato Networks
    {4909, "cato networks vpn", 90},
    --Avira Phantom VPN
    {4912, "avira.vpnservice", 90},
    --iTop VPN
    {4916, "itopvpn", 90},
    --wink
    {4961, "wink", 90},
    --DOTA 2
    {4971, "dota2", 90},
    --Pokerstars
    {4986, "pokerstars", 90},
    --League of Legends
    {5360, "league of legends", 90},
    --Gtarcade
    {5404, "gtarcade", 90},
    --2048 Game
    {5409, "2048 game", 90},
    --StarCraft II
    {5432, "starcraft ii", 90},
    --Epic Games
    {5440, "epic games", 90},
    --HearthStone
    {5443, "hearthstone", 90},
    --Township
    {5537, "township", 90},
    --Epic Games' Fortnite
    {5604, "fortnite", 90},
    --Gyazo Teams
    {5680, "gyazoteams", 90},
    --LiveAgent
    {5694, "liveagent", 90},
    --Redbooth
    {5729, "redbooth", 90},
    --Screenleap
    {5732, "screenleap", 90},
    --Miro
    {5737, "miro", 90},
    --Wickr
    {5753, "wickr", 90},
    --VidyoConnect
    {5764, "vidyoconnect", 90},
    --BAND
    {5799, "band", 90},
    --Amazon Chime
    {5817, "amazon chime", 90},
    --Loom
    {5824, "loom", 90},
    --Free Conference Call
    {5840, "freeconferencecall", 90},
    --Figma
    {5855, "figma", 90},
    --CloudMounter
    {5865, "cloudmounter", 90},
    --RaiDrive
    {5872, "raidrive", 90},
    --MagentaCloud
    {5880, "magentacloud", 90},
    --Nordlocker
    {5923, "nordlocker", 90},
    --Pcloud
    {5970, "pcloud", 90},
    --Cyberduck
    {6027, "cyberduck", 90},
    --Sync.com
    {6189, "sync.com", 90},
    --MinIO
    {6221, "minio", 90},
    --Docker
    {6257, "docker", 90},
    --Postman
    {6268, "postman", 90},
    --DeepL Translator
    {6269, "deepl translator", 90},
    --Notion
    {6270, "notion", 90},
    --Grafana
    {6271, "grafana", 90},
    --Jabra
    {6272, "jabra", 90},
    --Termius
    {6273, "termius", 90},
    --BoxCryptor
    {6274, "boxcryptor", 90},
    --Wrike
    {6275, "wrike", 90},
    --Calendly
    {6276, "calendly", 90},
    --Tabnine
    {6277, "tabnine", 90},
    --1Password
    {6278, "1password", 90},
    --SmartDraw
    {6293, "smartdraw", 90},
    --LightShot
    {6296, "lightshot", 90},
    --Slides
    {6298, "slides", 90},
    --WinZip
    {6301, "winzip", 90},
    --RescueTime
    {6303, "rescuetime", 90},
    --XMind
    {6305, "xmind", 90},
    --TimeCamp
    {6321, "timecamp", 90},
    --Monday
    {6326, "monday", 90},
    --SketchUp
    {6332, "sketchup", 90},
    --Flow
    {6337, "flow", 90},
    --Toggl Track
    {6348, "toggl track", 90},
    {6348, "toggltrack", 90},
    --Todoist
    {6351, "todoist", 90},
    --iLovePDF
    {6359, "ilovepdf", 90},
    --ProtonMail
    {6367, "proton mail", 90},
    --Jisupdf
    {6372, "jisupdf", 90},
    --Keyshot
    {6377, "keyshot", 90},
    --Zeplin
    {6387, "zeplin", 90},
    --Airtable
    {6403, "airtable", 90},
    --Screencast-O-Matic
    {6532, "screencast-o-matic", 90},
    --Autopilot
    {6653, "autopilot", 90},
    --VPN Unlimited
    {6848, "vpn unlimited", 90},
    --Private Internet Access
    {6878, "private internet access", 90},
    --Pulse Secure
    {6899, "pulse secure", 90},
    --Syncthing
    {6959, "syncthing", 90},
    --Trillian
    {7020, "trillian", 90},
    --Dashlane
    {7063, "dashlane", 90},
    --Remote Desktop Manager
    {7071, "remote desktop manager", 90},
    {7071, "remotedesktopmanager", 90},
    --Ccleaner Cloud
    {7118, "ccleaner", 90},
    --Maxthon
    {7139, "maxthon", 90},
    --TradingView
    {7160, "tradingview", 90},
    --Fitbit
    {7174, "fitbit", 90},
    --Smallpdf
    {7182, "smallpdf", 90},
    --Tesla
    {7338, "tesla", 90},
    --ChatGPT
    {7358, "chatgpt", 90},
    --Potato VPN
    {7364, "potato vpn", 90},
}

function DetectorInit(detectorInstance)
    gDetector = detectorInstance;
    if gDetector.addProcessToClientMapping then
        for i,v in ipairs(gProcessClientList) do
            gDetector:addProcessToClientMapping(v[1], v[2], v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end