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
detection_name: Payload Group "350"
version: 21
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Spinrilla' => 'Free hip hop mixed tape downloads.',
          'ICICI Bank' => 'Indian multinational banking and financial services company.',
          'SaveFrom' => 'Software that allows you to download files and videos from almost all popular video sharing networks.',
          'Fluent' => 'Marketing and analytics.',
          'Betclic' => 'Online gambling site.',
          'skyZIP' => 'Browser extenstion that uses various techniques to speed web browsing.',
          'Ouoio.io' => 'URL shortening service where you can shorten you links to make money from it.',
          'RarBG' => 'Website provides torrent files and magnet links to facilitate peer-to-peer file sharing using the BitTorrent protocol.',
          'Baydin' => 'Gmail productivity app.',
          'HOLACOM' => 'Spanish news Website.',
          'GamerCom' => 'An internet forum for video games, comics, animation in taiwan.',
          'Diply' => 'Social news and entertainment with trending contents.',
          'Ad Marvel' => 'Web advertisement services.',
          'Niantic Labs' => 'Makers of popular augmented reality games Pokemon Go and Ingress.',
          'ITV' => 'Streaming video provider.',
          'BRSRVR' => 'A content delivery network.',
          'Clash Royale' => 'A web and mobile-based game spun off from Clash of Clans.',
          'Xnxx' => 'Adult Videos.',
          'DirectREV' => 'Real-time digital ad marketplace to connects publishers with agencies and ad networks.',
          'GREE Games' => 'A Japanese social network and mobile gaming site.',
          'SO.com' => 'Chinese internet search engine.',
          'HDFC Bank' => 'Indian banking and financial services company.',
          'Pogo' => 'Online games.',
          'Openload' => 'Movies online.',
          'Advanced Hosters' => 'Content delivery network.',
          'SlideRocket' => 'Cloud based presentation software.',
          'SAP HostControl' => 'SAP Host Control Agent protocol used for viewing logs and traces of a remote host.',
          'Bilibili' => 'Chinese site for uploading and discussing anime.',
          'Sahibinden' => 'An online classifieds and shopping platform.',
          'ImpressCoJp' => 'General impress.co.jp website traffic.',
          'Supercell' => 'Web-based game publisher.',
          'PopCap Games' => 'Online games website.',
          'Cricbuzz.com' => 'Online site to provide live Cricket updates.',
          'Pokemon Go' => 'A popular mobile augmented reality game.',
          'Ppomppu' => 'South Korean news/blogs portal.',
          'Dainik Bhaskar' => 'Hindi online news portal.',
          'Cvent' => 'Event registration software.',
          'RedTube' => 'Adult Videos.',
          'Sina' => 'A Chinese internet company that produces microblogging and social networking apps.',
          'OnClick' => 'Browser redirector.',
          'AZLyrics' => 'Website for sharing and cataloging song lyric transcriptions.',
          'DINGIT.TV' => 'Sports highlights and online game portal.',
          'Slingbox' => 'Media streaming from a television to the internet.',
          'Syncplicity' => 'Data synch service.',
          'Pathview' => 'An AppNeta performance metric tool.',
          'AppNeta' => 'Web application performance metrics and analytics.',
          'GAMERSKY' => 'Entertainment media that focuses on stand-alone games.',
          'SoundHound' => 'Music search and audio hands-free app.',
          'Coc Coc' => 'Vietnamese search engine and advertising platform.',
          'Clip Converter' => 'Free online video converter application.',
          'DocuSign' => 'Secure electronic document signing.',
          'PrivateHomeClips' => 'Adult videos.',
          'Milliyet' => 'Turkish daily newspaper published in Istanbul.',
          'Yandex Maps' => 'Online maps provided by Yandex.',
          'detikcom' => 'Indonesian online news portal.',
          'GISMETEO' => 'Website providing wheather forecasts for different areas in Russia.',
          'Yandex AppMetrica' => 'Yandex analytics.',
          'Middle East Broadcasting Center' => 'Web site of Arabic private free-to-air satellite broadcasting company.',
          'Shorte' => 'URL shortener company that pays for clicks.',
          'GearBest' => 'Platform for user feedbacks, suggestions, promotions and giveaways.',
          'Getscreen.me' => 'Remote Desktop Access. Cloud-based software for administration, technical support and remote work.',
          'Giganews' => 'A popular Usenet/newsgroup service provider.',
          'LiveJasmin' => 'Adult content videos.',
          'HubSpot' => 'Developer/Marketer of software products for inbound marketing and sales.',
          'eBay Search' => 'Browsing eBay listings.',
          'Sabah' => 'Turkish news website.',
          'TripIt' => 'Cloud based travel planner.',
          'Ruten' => 'A Taiwanese online auction and shopping website.',
          'SpankBang' => 'Adult videos.',
          'MobileCore' => 'Mobile ad and media service.',
          'Shopify' => 'eCommerce Web based Platform.',
          'Eastday' => 'Chinese news portal.',
          'Douyu' => 'Chinese portal for live video games.',
          'Windows Live Hotmail' => 'Microsoft\'s free web-based email service.',
          'Hatena Blog' => 'Internet services company in Japan.',
          'Seznam' => 'Web portal and search engine in the Czech Republic.',
          'AcFun' => 'Video sharing site.',
          'Eve Online' => 'Science fiction multi player online game.',
          'ABS-CBN' => 'Phillipines-based news.',
          'FRIV' => 'Free online gaming site.',
          'CCTV.com' => 'China Central Television site.',
          'Cloudsponge' => 'Contact importer for various email services.',
          'Uploaded' => 'Cloud storage and backup.',
          'C3 Metrics' => 'Visiting websites that use C3 Metrics to deliver advertisements.',
          'UEFA' => 'European Football league.',
          'AVG' => 'AVG Antivirus/Security software download and updates.',
          'PHP' => 'Scripting language for developing server based web applications.',
          'Scribol' => 'Online magazine covering bizarre and eclectic news on the internet.',
          'Inspectlet' => 'Website informatics and analytics.',
          'Hurriyet' => 'Turkish news Website.',
          'HandyCafe' => 'Internet Cafe Software.',
          'Yandex Translate' => 'Online translation form Yandex.',
          'Tokbox' => 'Video and voice messaging for eBuddy using RTMP.',
          'ScienceDirect' => 'A website which provides subscription-based access to a large databas of scientific and medical research.',
          'Gothere' => 'Navigation app for finding directions and places in Singapore.',
          'Asana' => 'Collboration service.',
          'ExoClick' => 'Barcelona based advertising company for both advertisers and publishers.',
          'WarLight' => 'Online game like Risk.',
          'Kugou' => 'Peer-to-peer music.',
          'Rapidgator' => 'File hosting site.',
          'Fingta' => 'Web Services, Malware and Ads.',
          'Avira Download/Update' => 'Avira Antivirus/Security software download and updates.',
          'BuzzHand' => 'Content creation site for articles and collaboration.',
          'GameSpot' => 'Video game previews/reviews/news website.',
          'CloudApp' => 'Data synch and collaboration app.',
          'Qatar Living' => 'Guide about living in Qatar.',
          'Seasonvar' => 'Russian free online film streaming.',
          'OkeZone' => 'Web site delivering the latest news in Indonesia.',
          'Suning' => 'Chinese retailer company.',
          'ReImage' => 'Online computer repair.',
          'Eksi sozluk' => 'Turkish online dictionary.',
          'Ninite' => 'A tool that manages installation and upgrading of apps.',
          'Elmogaz' => 'Egyptian online news portal.',
          'Tabelog' => 'Search/rank restaurants in Japan.',
          'Cnblogs' => 'Chinese discussion forum for programmers.',
          'Gulf Times' => 'Daily Newspaper published by GPPC Doha, Qatar.',
          'CrashPlan' => 'Cloud-based enterprise backup solution.',
          'EL PAIS' => 'Spanish daily newspaper portal.',
          'Ad Redirector' => 'Ad service.',
          'Slingbox Media' => 'Streaming media via Slingbox.',
          'Slither' => 'Multiplayer browser game.',
          'ShopStyle' => 'Fashion search engine which links to various retailers.',
          'Sberbank of Russia' => 'A state-owned Russian banking and financial services company.',
          'InQuest Technologies' => 'Cloud based business automation service.',
          'MyWay' => 'Adware and spyware, categorized as an internet browser hijacker.',
          'Usenet' => 'A worldwide distributed Internet discussion forum.',
          'IMzog' => 'Adult videos.',
          'Jungle Disk' => 'Cloud storage and backup.',
          'Snapdeal' => 'Indian e-commerce company.',
          'H&M' => 'Website of a clothing-retail company.',
          'Likes' => 'Entertainment website with dynamic content.',
          'MSN' => 'Portal for news, video, and other content.',
          'BillDesk' => 'Online payment consolidation site.',
          'Yandex Market' => 'Yandex shopping.',
          'Flixster' => 'A movie-based social networking site allowing users to share ratings and recommendations. Available Facebook app.',
          'Upornia' => 'Adult content videos.',
          'Babytree' => 'Website with resources and shopping for expectant mothers.',
          'Yandex Money' => 'Financial and stock market news from Yandex.',
          'RuTracker' => 'Russian torrent site.',
          'Gantter' => 'Online project management resource.',
          'CNNIC' => 'China Internet Network Infromation Center is reponsible for handling domain name registrations.',
          'Viber' => 'Smartphone app that allows for free phone calls and text messages.',
          'Digikala' => 'Online shopping and review forum from Iran.',
          'GIPHY' => 'Online database & search engine for animated GIF files.',
          'DMM' => 'Japan-based e-commerce portal for purchasing goods and services like e-books, games, VOD, 3D priting.',
          'Globo' => 'Mass media group of Latin America, founded in Rio de Janeiro.',
          'Google Safebrowsing' => 'Website blacklisting service.',
          'BRCDN' => 'A content delivery network.',
          'Ci123' => 'Chinese marketing and ad service.',
          'Caijing' => 'Chinese independant news resource.',
          'asos' => 'Clothing and fashion brand.',
          'Haber7' => 'Turkish news Website.',
          'Frozenway' => 'VPN for bypassing firewalls.',
          'ekantipur' => 'Kantipur online news portal.',
          'Betternet' => 'A VPN tunneling app.',
          'Qatar Government' => 'Qatar Government website.',
          'SiteAdvisor' => 'Service that reports on the safety of web sites.',
          'I2P' => 'Invisible Internet Protocol, an anonymous p2p network.',
          'Urban Outfitters' => 'Clothing and footwear retailer.',
          'Anghami' => 'Music streaming site.',
          'Huanqiu' => 'Chinese dialy newspaper.',
          'Freepik' => 'Search engine for free vector & graphic designs.',
          'Lucidchart' => 'Web analytics services.',
          'ETtoday' => 'Chinese online news portal.',
          'SpiderOak' => 'Cloud storage and backup.',
          'GSMArena' => 'Web site providing information about mobile phones.',
          'Trello' => 'Collaboration tool that organizes projects into boards.',
          'eBay Watch' => 'Watching an item on eBay.',
          'Gfycat' => 'User-generated short video hosting company.',
          'Subscene' => 'Provides subtitles in more than 50 languages.',
          'Olx.pl' => 'Platform to connect local people to buy, sell or exchange used goods and services through their mobile phone or on the web.',
          'Boomerang' => 'Gmail send and receive scheduling.',
          'BlueJeans' => 'An interoperable cloud-based video conferencing service.',
          'Blasting News' => 'Citizen journalism site.',
          'Clicksgear' => 'Suspicious Adware.',
          'Yandex Email' => 'Webmail provided by Yandex.',
          'Instructure' => 'Online portal for teaching and learning.',
          'Qatar University' => 'Qatar University in Doha.',
          'Mojang' => 'Video game developer and publisher.',
          'Bitauto' => 'Marketing and advertising service for Chinese auto industry.',
          'Veoh' => 'Internet television and video sharing service.',
          'Zomato' => 'Online restaraunt database.',
          'Code42' => 'Enterprise data management and security software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_350",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Ad Marvel
	{ 0, 0, 0, 496, 1, "map.admarvel.com", "/", "http:", "", 1308 },
	--eBay Search
	{ 0, 0, 0, 33, 1, "shop.ebay.com", "/", "http:", "", 134 },
	--eBay Watch
	{ 0, 0, 0, 34, 1, "cgi1.ebay.com", "/", "http:", "", 135 },
	--Flixster
	{ 0, 0, 0, 2125, 1, "flixster.com", "/", "http:", "", 160 },
	--Giganews
	{ 0, 0, 0, 2135, 1, "giganews.com", "/", "http:", "", 175 },
	--Windows Live Hotmail
	{ 0, 0, 0, 22, 1, "hotmail.com", "/", "http:", "", 205 },
	--PHP
	{ 0, 0, 0, 2178, 1, "php.net", "/", "http:", "", 2230 },
	--Viber
	{ 0, 0, 0, 2222, 1, "viber.com", "/", "http:", "", 2367 },
	--Tokbox
	{ 0, 0, 0, 2216, 1, "tokbox.com", "/", "http:", "", 2400 },
	--Mediaplex
	--{ 0, 0, 0, 2164, 1, "mediaplex.com", "/", "http:", "", 2407 },
	--BRSRVR
	{ 0, 0, 0, 2087, 1, "cdn.brsrvr.com", "/", "http:", "", 2457 },
	--BRCDN
	{ 0, 0, 0, 2086, 1, "p1.brcdn.com", "/", "http:", "", 2459 },
	--Kugou
	{ 0, 0, 0, 832, 1, "static.kugou.com", "/", "http:", "", 256 },
	--MSN
	{ 0, 0, 0, 52, 1, "msn.co.uk", "/", "http:", "", 308 },
	--Fluent
	{ 0, 0, 0, 2126, 1, "fluentmobile.com", "/", "http:", "", 3658 },
	--Sina
	{ 0, 0, 0, 2200, 1, "sina.com", "/", "http:", "", 3675 },
	--Betclic
	{ 0, 0, 0, 2078, 1, "en.betclic.com", "/", "http:", "", 3703 },
	--AppNeta
	{ 0, 0, 0, 2068, 1, "appneta.com", "/", "http:", "", 3742 },
	--Pathview
	{ 0, 0, 0, 2177, 1, "pathviewcloud.com", "/", "http:", "", 3752 },
	--Slingbox Media
	{ 0, 0, 0, 2204, 1, "sso.slingmedia.com", "/", "http:", "", 3753 },
	--C3 Metrics
	{ 0, 0, 0, 2089, 1, "c3metrics.com", "/", "http:", "", 3819 },
	--GREE Games
	{ 0, 0, 0, 2140, 1, "gree.net", "/", "http:", "", 3852 },
	--ITV
	{ 0, 0, 0, 2159, 1, "tom.itv.com", "/", "http:", "", 3859 },
	--Code42
	{ 0, 0, 0, 2102, 1, "code42.com", "/", "http:", "", 3877 },
	--CrashPlan
	{ 0, 0, 0, 2104, 1, "crashplan.com", "/", "http:", "", 3878 },
	--Asana
	{ 0, 0, 0, 2071, 1, "asana.com", "/", "http:", "", 3950 },
	--Baydin
	{ 0, 0, 0, 2077, 1, "baydin.com", "/", "http:", "", 3951 },
	--Boomerang
	{ 0, 0, 0, 2085, 1, "boomeranggmail.com", "/", "http:", "", 3952 },
	--Cloudsponge
	{ 0, 0, 0, 2098, 1, "cloudsponge.com", "/", "http:", "", 3953 },
	--Cvent
	{ 0, 0, 0, 2106, 1, "cvent.com", "/", "http:", "", 3954 },
	--DocuSign
	{ 0, 0, 0, 2114, 1, "docusign.com", "/", "http:", "", 3955 },
	--Gantter
	{ 0, 0, 0, 2132, 1, "gantter.com", "/", "http:", "", 3957 },
	--InQuest Technologies
	{ 0, 0, 0, 2156, 1, "inquesttechnologies.com", "/", "http:", "", 3959 },
	--Inspectlet
	{ 0, 0, 0, 2157, 1, "inspectlet.com", "/", "http:", "", 3960 },
	--Lucidchart
	{ 0, 0, 0, 2163, 1, "lucidchart.com", "/", "http:", "", 3961 },
	--SlideRocket
	{ 0, 0, 0, 2203, 1, "sliderocket.com", "/", "http:", "", 3963 },
	--TripIt
	{ 0, 0, 0, 2218, 1, "tripit.com", "/", "http:", "", 3965 },
	--UEFA
	{ 0, 0, 0, 2219, 1, "uefa.com", "/", "http:", "", 3966 },
	--WarLight
	{ 0, 0, 0, 2223, 1, "warlight.net", "/", "http:", "", 3967 },
	--Zomato
	{ 0, 0, 0, 2230, 1, "zomato.com", "/", "http:", "", 3968 },
	--Eve Online
	{ 0, 0, 0, 2122, 1, "eveonline.com", "/", "http:", "", 4004 },
	--Mojang
	{ 0, 0, 0, 2168, 1, "mojang.com", "/", "http:", "", 4006 },
	--CloudApp
	{ 0, 0, 0, 2097, 1, "my.cl.ly", "/", "http:", "", 4021 },
	--Rapidgator
	{ 0, 0, 0, 2184, 1, "rapidgator.net", "/", "http:", "", 4024 },
	--Syncplicity
	{ 0, 0, 0, 2214, 1, "syncplicity.com", "/", "http:", "", 4027 },
	--I2P
	{ 0, 0, 0, 2152, 1, "geti2p.net", "/", "http:", "", 4033 },
	--Jungle Disk
	{ 0, 0, 0, 2162, 1, "jungledisk.com", "/", "http:", "", 4034 },
	--Ninite
	{ 0, 0, 0, 2171, 1, "ninite.com", "/", "http:", "", 4035 },
	--SpiderOak
	{ 0, 0, 0, 2209, 1, "spideroak.com", "/", "http:", "", 4036 },
	--Uploaded
	{ 0, 0, 0, 2220, 1, "uploaded.net", "/", "http:", "", 4037 },
	--Spinrilla
	{ 0, 0, 0, 2210, 1, "spinrilla.com", "/", "http:", "", 4044 },
	--skyZIP
	{ 0, 0, 0, 2202, 1, "skyzip.de", "/", "http:", "", 4047 },
	--Yandex AppMetrica
	{ 0, 0, 0, 2224, 1, "appmetrica.yandex.com", "/", "http:", "", 4059 },
	--Yandex Email
	{ 0, 0, 0, 2225, 1, "mail.yandex.com", "/", "http:", "", 4061 },
	--Yandex Maps
	{ 0, 0, 0, 2226, 1, "suggest-maps.yandex.ru", "/", "http:", "", 4062 },
	--Yandex Money
	{ 0, 0, 0, 2228, 1, "money.yandex.com", "/", "http:", "", 4063 },
	--Yandex Market
	{ 0, 0, 0, 2227, 1, "market.yandex.ru", "/", "http:", "", 4064 },
	--Yandex Translate
	{ 0, 0, 0, 2229, 1, "translate.yandex.com", "/", "http:", "", 4066 },
	--MobileCore
	{ 0, 0, 0, 2167, 1, "mobilecore.com", "/", "http:", "", 4086 },
	--Betternet
	{ 0, 0, 0, 2079, 1, "betternet.co", "/", "http:", "", 4092 },
	--Frozenway
	{ 0, 0, 0, 2129, 1, "frozendo.com", "/", "http:", "", 4096 },
	--Supercell
	{ 0, 0, 0, 2213, 1, "supercell.com", "/", "http:", "", 4097 },
	--Clash Royale
	{ 0, 0, 0, 2094, 1, "clashroyale.com", "/", "http:", "", 4098 },
	--SAP HostControl
	{ 0, 0, 0, 2191, 1, "sap.com", "/", "http:", "", 410 },
	--SoundHound
	{ 0, 0, 0, 2208, 1, "soundhound.com", "/", "http:", "", 4102 },
	--Anghami
	{ 0, 0, 0, 2065, 1, "anghami.com", "/", "http:", "", 4103 },
	--Niantic Labs
	{ 0, 0, 0, 2170, 1, "nianticlabs.com", "/", "http:", "", 4104 },
	--Pokemon Go
	{ 0, 0, 0, 2179, 1, "pokemongo.com", "/", "http:", "", 4105 },
	--Gothere
	{ 0, 0, 0, 2139, 1, "gothere.sg", "/", "http:", "", 4131 },
	--BlueJeans
	{ 0, 0, 0, 2084, 1, "bluejeans.com", "/", "http:", "", 4151 },
	--Openload
	{ 0, 0, 0, 2175, 1, "openload.co", "/", "http:", "", 4159 },
	--ABS-CBN
	{ 0, 0, 0, 2052, 1, "abs-cbn.com", "/", "http:", "", 4168 },
	--AcFun
	{ 0, 0, 0, 2053, 1, "acfun.cn", "/", "http:", "", 4169 },
	--Ad Redirector
	{ 0, 0, 0, 2055, 1, "adexchangeprediction.com", "/", "http:", "", 4170 },
	--Advanced Hosters
	{ 0, 0, 0, 2061, 1, "ahcdn.com", "/", "http:", "", 4171 },
	--asos
	{ 0, 0, 0, 2072, 1, "asos.com", "/", "http:", "", 4174 },
	--AZLyrics
	{ 0, 0, 0, 2075, 1, "azlyrics.com", "/", "http:", "", 4176 },
	--Babytree
	{ 0, 0, 0, 2076, 1, "babytree.com", "/", "http:", "", 4177 },
	--Qatar Government
	{ 0, 0, 0, 2181, 1, "portal.www.gov.qa", "/", "http:", "", 4183 },
	--Qatar Living
	{ 0, 0, 0, 2182, 1, "qatarliving.com", "/", "http:", "", 4184 },
	--Qatar University
	{ 0, 0, 0, 2183, 1, "qu.edu.qa", "/", "http:", "", 4185 },
	--RarBG
	{ 0, 0, 0, 2185, 1, "rarbg.to", "/", "http:", "", 4190 },
	--RedTube
	{ 0, 0, 0, 2054, 1, "redtube.com", "/", "http:", "", 4191 },
	--ReImage
	{ 0, 0, 0, 2186, 1, "reimageplus.com", "/", "http:", "", 4192 },
	--Ruten
	{ 0, 0, 0, 2187, 1, "ruten.com.tw", "/", "http:", "", 4196 },
	--RuTracker
	{ 0, 0, 0, 2188, 1, "rutracker.org", "/", "http:", "", 4197 },
	--Sabah
	{ 0, 0, 0, 2189, 1, "sabah.com.tr", "/", "http:", "", 4198 },
	--Sahibinden
	{ 0, 0, 0, 2190, 1, "sahibinden.com", "/", "http:", "", 4199 },
	--SaveFrom
	{ 0, 0, 0, 2192, 1, "en.savefrom.net", "/", "http:", "", 4200 },
	--Sberbank of Russia
	{ 0, 0, 0, 2193, 1, "sberbank.ru", "/", "http:", "", 4201 },
	--ScienceDirect
	{ 0, 0, 0, 2194, 1, "sciencedirect.com", "/", "http:", "", 4203 },
	--Middle East Broadcasting Center
	{ 0, 0, 0, 2165, 1, "mbc.net", "/", "http:", "", 4206 },
	--Milliyet
	{ 0, 0, 0, 2166, 1, "milliyet.com.tr", "/", "http:", "", 4210 },
	--MyWay
	{ 0, 0, 0, 2169, 1, "hp.myway.com", "/", "http:", "", 4211 },
	--OkeZone
	{ 0, 0, 0, 2172, 1, "okezone.com", "/", "http:", "", 4220 },
	--Olx.pl
	{ 0, 0, 0, 2173, 1, "olx.pl", "/", "http:", "", 4221 },
	--OnClick
	{ 0, 0, 0, 2174, 1, "onclkds.com", "/", "http:", "", 4222 },
	--Ouoio.io
	{ 0, 0, 0, 2176, 1, "ouo.io", "/", "http:", "", 4227 },
	--Ppomppu
	{ 0, 0, 0, 2180, 1, "ppomppu.co.kr", "/", "http:", "", 4237 },
	--PrivateHomeClips
	{ 0, 0, 0, 2051, 1, "hclips.com", "/", "http:", "", 4238 },
	--Bilibili
	{ 0, 0, 0, 2080, 1, "bilibili.com", "/", "http:", "", 4240 },
	--BillDesk
	{ 0, 0, 0, 2081, 1, "billdesk.com", "/", "http:", "", 4241 },
	--Bitauto
	{ 0, 0, 0, 2082, 1, "bitauto.com", "/", "http:", "", 4242 },
	--Blasting News
	{ 0, 0, 0, 2083, 1, "blastingnews.com", "/", "http:", "", 4243 },
	--BuzzHand
	{ 0, 0, 0, 2088, 1, "buzzhand.com", "/", "http:", "", 4248 },
	--Caijing
	{ 0, 0, 0, 2090, 1, "caijing.com.cn", "/", "http:", "", 4249 },
	--CCTV.com
	{ 0, 0, 0, 2091, 1, "cctv.com", "/", "http:", "", 4251 },
	--Ci123
	{ 0, 0, 0, 2092, 1, "ci123.com", "/", "http:", "", 4254 },
	--Fingta
	{ 0, 0, 0, 2124, 1, "rudateblue2.fingta.com", "/", "http:", "", 4255 },
	--Freepik
	{ 0, 0, 0, 2127, 1, "freepik.com", "/", "http:", "", 4256 },
	--FRIV
	{ 0, 0, 0, 2128, 1, "friv.com", "/", "http:", "", 4257 },
	--GamerCom
	{ 0, 0, 0, 2130, 1, "gamer.com.tw", "/", "http:", "", 4258 },
	--GAMERSKY
	{ 0, 0, 0, 2131, 1, "gamersky.com", "/", "http:", "", 4259 },
	--GearBest
	{ 0, 0, 0, 2133, 1, "gearbest.com", "/", "http:", "", 4260 },
	--Gfycat
	{ 0, 0, 0, 2134, 1, "gfycat.com", "/", "http:", "", 4261 },
	--GIPHY
	{ 0, 0, 0, 2136, 1, "giphy.com", "/", "http:", "", 4262 },
	--GISMETEO
	{ 0, 0, 0, 2137, 1, "gismeteo.ru", "/", "http:", "", 4263 },
	--Globo
	{ 0, 0, 0, 2138, 1, "globo.com", "/", "http:", "", 4264 },
	--GSMArena
	{ 0, 0, 0, 2141, 1, "gsmarena.com", "/", "http:", "", 4265 },
	--Gulf Times
	{ 0, 0, 0, 2142, 1, "gulf-times.com", "/", "http:", "", 4266 },
	--Haber7
	{ 0, 0, 0, 2144, 1, "haber7.com", "/", "http:", "", 4267 },
	--HandyCafe
	{ 0, 0, 0, 2145, 1, "handycafe.com", "/", "http:", "", 4268 },
	--Hatena Blog
	{ 0, 0, 0, 2146, 1, "hatenablog.com", "/", "http:", "", 4269 },
	--HDFC Bank
	{ 0, 0, 0, 2147, 1, "hdfcbank.com", "/", "http:", "", 4270 },
	--H&M
	{ 0, 0, 0, 2143, 1, "hm.com", "/", "http:", "", 4271 },
	--HOLACOM
	{ 0, 0, 0, 2148, 1, "hola.com", "/", "http:", "", 4272 },
	--Huanqiu
	{ 0, 0, 0, 2149, 1, "huanqiu.com", "/", "http:", "", 4273 },
	--HubSpot
	{ 0, 0, 0, 2150, 1, "hubspot.com", "/", "http:", "", 4274 },
	--Hurriyet
	{ 0, 0, 0, 2151, 1, "hurriyet.com.tr", "/", "http:", "", 4275 },
	--ICICI Bank
	{ 0, 0, 0, 2153, 1, "icicibank.com", "/", "http:", "", 4276 },
	--ImpressCoJp
	{ 0, 0, 0, 2154, 1, "impress.co.jp", "/", "http:", "", 4277 },
	--IMzog
	{ 0, 0, 0, 2048, 1, "imzog.com", "/", "http:", "", 4278 },
	--Scribol
	{ 0, 0, 0, 2195, 1, "scribol.com", "/", "http:", "", 4279 },
	--Seasonvar
	{ 0, 0, 0, 2196, 1, "seasonvar.ru", "/", "http:", "", 4280 },
	--Seznam
	{ 0, 0, 0, 2197, 1, "onas.seznam.cz", "/", "http:", "", 4281 },
	--Shopify
	{ 0, 0, 0, 2198, 1, "shopify.com", "/", "http:", "", 4282 },
	--Shorte
	{ 0, 0, 0, 2199, 1, "shorte.st", "/", "http:", "", 4283 },
	--SiteAdvisor
	{ 0, 0, 0, 2201, 1, "siteadvisor.com", "/", "http:", "", 4284 },
	--Slither
	{ 0, 0, 0, 2205, 1, "slither.io", "/", "http:", "", 4285 },
	--Snapdeal
	{ 0, 0, 0, 2206, 1, "snapdeal.com", "/", "http:", "", 4286 },
	--SO.com
	{ 0, 0, 0, 2207, 1, "so.com", "/", "http:", "", 4287 },
	--SpankBang
	{ 0, 0, 0, 2060, 1, "spankbang.com", "/", "http:", "", 4289 },
	--Subscene
	{ 0, 0, 0, 2211, 1, "subscene.com", "/", "http:", "", 4290 },
	--Suning
	{ 0, 0, 0, 2212, 1, "suning.com", "/", "http:", "", 4291 },
	--Tabelog
	{ 0, 0, 0, 2215, 1, "tabelog.com", "/", "http:", "", 4292 },
	--Trello
	{ 0, 0, 0, 2217, 1, "trello.com", "/", "http:", "", 4300 },
	--Clicksgear
	{ 0, 0, 0, 2095, 1, "clicksgear.com", "/", "http:", "", 4306 },
	--Clip Converter
	{ 0, 0, 0, 2096, 1, "clipconverter.cc", "/", "http:", "", 4307 },
	--Cnblogs
	{ 0, 0, 0, 2099, 1, "cnblogs.com", "/", "http:", "", 4308 },
	--CNNIC
	{ 0, 0, 0, 2100, 1, "cnnic.cn", "/", "http:", "", 4309 },
	--Coc Coc
	{ 0, 0, 0, 2101, 1, "coccoc.com", "/", "http:", "", 4311 },
	--Conservative Tribune
	--{ 0, 0, 0, 2103, 1, "conservativetribune.com", "/", "http:", "", 4312 },
	--Cricbuzz.com
	{ 0, 0, 0, 2105, 1, "cricbuzz.com", "/", "http:", "", 4313 },
	--Dainik Bhaskar
	{ 0, 0, 0, 2107, 1, "bhaskar.com", "/", "http:", "", 4315 },
	--detikcom
	{ 0, 0, 0, 2108, 1, "detik.com", "/", "http:", "", 4317 },
	--Digikala
	{ 0, 0, 0, 2109, 1, "digikala.com", "/", "http:", "", 4319 },
	--Slingbox
	{ 0, 0, 0, 64, 1, "slingmedia.com", "/", "http:", "", 432 },
	--DINGIT.TV
	{ 0, 0, 0, 2110, 1, "dingit.tv", "/", "http:", "", 4320 },
	--Diply
	{ 0, 0, 0, 2111, 1, "diply.com", "/", "http:", "", 4321 },
	--DirectREV
	{ 0, 0, 0, 2112, 1, "directrev.com", "/", "http:", "", 4322 },
	--DMM
	{ 0, 0, 0, 2113, 1, "dmm.com", "/", "http:", "", 4323 },
	--Douyu
	{ 0, 0, 0, 2115, 1, "douyu.com", "/", "http:", "", 4324 },
	--Eastday
	{ 0, 0, 0, 2116, 1, "eastday.com", "/", "http:", "", 4325 },
	--ekantipur
	{ 0, 0, 0, 2117, 1, "ekantipur.com", "/", "http:", "", 4326 },
	--Eksi sozluk
	{ 0, 0, 0, 2118, 1, "eksisozluk.com", "/", "http:", "", 4327 },
	--Elmogaz
	{ 0, 0, 0, 2120, 1, "elmogaz.com", "/", "http:", "", 4328 },
	--EL PAIS
	{ 0, 0, 0, 2119, 1, "elpais.com", "/", "http:", "", 4329 },
	--ETtoday
	{ 0, 0, 0, 2121, 1, "ettoday.net", "/", "http:", "", 4330 },
	--ExoClick
	{ 0, 0, 0, 2123, 1, "exoclick.com", "/", "http:", "", 4331 },
	--Instructure
	{ 0, 0, 0, 2158, 1, "instructure.com", "/", "http:", "", 4332 },
	--Likes
	{ 0, 0, 0, 2160, 1, "likes.com", "/", "http:", "", 4349 },
	--LiveJasmin
	{ 0, 0, 0, 2049, 1, "livejasmin.com", "/", "http:", "", 4351 },
	--Upornia
	{ 0, 0, 0, 2062, 1, "upornia.com", "/", "http:", "", 4355 },
	--Xnxx
	{ 0, 0, 0, 2063, 1, "xnxx.com", "/", "http:", "", 4378 },
	--AVG
	{ 0, 0, 0, 2066, 1, "avg.com", "/", "http:", "", 44 },
	--Avira Download/Update
	{ 0, 0, 0, 2074, 1, "avira.com", "/", "http:", "", 45 },
	--Getscreen.me
	{ 0, 0, 0, 2231, 1, "getscreen.me", "/", "http:", "", 4660 },
	--Usenet
	{ 0, 0, 0, 2221, 1, "usenetserver.com", "/", "http:", "", 487 },
	--GameSpot
	{ 0, 0, 0, 121, 1, "gamespot.com", "/", "http:", "", 648 },
	--Google Safebrowsing
	{ 0, 0, 0, 40, 1, "safebrowsing-cache.google.com", "/", "http:", "", 665 },
	--Pogo
	{ 0, 0, 0, 58, 1, "pogo.com", "/", "http:", "", 787 },
	--PopCap Games
	{ 0, 0, 0, 256, 1, "popcap.com", "/", "http:", "", 789 },
	--ShopStyle
	{ 0, 0, 0, 265, 1, "shopstyle.com", "/", "http:", "", 828 },
	--Urban Outfitters
	{ 0, 0, 0, 275, 1, "urbanoutfitters.com", "/", "http:", "", 883 },
	--Veoh
	{ 0, 0, 0, 276, 1, "veoh.com", "/", "http:", "", 889 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
