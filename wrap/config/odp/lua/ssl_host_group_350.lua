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
detection_name: SSL Group "350"
version: 20
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'OsiriX' => 'Image processing tool for DICOM images.',
          'Yandex Translate' => 'Online translation form Yandex.',
          'Trulia' => 'Online portal for Real Estate.',
          'Slingbox' => 'Media streaming from a television to the internet.',
          'eBay Search' => 'Browsing eBay listings.',
          'BlueJeans' => 'An interoperable cloud-based video conferencing service.',
          'Proclivity' => 'Advertisement site.',
          'Freepik' => 'Search engine for free vector & graphic designs.',
          'Fark' => 'News link sharing and discussion.',
          'CloudApp' => 'Data synch and collaboration app.',
          'AudioDocumentary.org' => 'Online archive of public-domain audio and video documentaries.',
          'RedTube' => 'Adult Videos.',
          'Deals Direct' => 'Australian discount retailer.',
          'SopCast' => 'P2P audio and video streaming.',
          'Hightail' => 'Secure file transfer service. Formerly Yousendit.',
          'Huanqiu' => 'Chinese dialy newspaper.',
          'Blasting News' => 'Citizen journalism site.',
          'Neopets' => 'Virtual pet website.',
          'CrashPlan' => 'Cloud-based enterprise backup solution.',
          'CCTV.com' => 'China Central Television site.',
          'Google Adsense' => 'Provides a way for website owners to earn money from their online content.',
          'Cloudsponge' => 'Contact importer for various email services.',
          'TransferBigFiles.com' => 'File hosting and sharing service.',
          'MSDN' => 'Microsoft Developer Network.',
          'Netflix stream' => 'Video streams from Netflix service.',
          'HDFC Bank' => 'Indian banking and financial services company.',
          'HandyCafe' => 'Internet Cafe Software.',
          'Ensighten' => 'Tag-based advertising platform.',
          'DivShare' => 'File hosting and sharing service.',
          'Hupu' => 'Sports news website.',
          'Ad Marvel' => 'Web advertisement services.',
          'Undertone' => 'Advertisement site.',
          'asos' => 'Clothing and fashion brand.',
          'Urban Outfitters' => 'Clothing and footwear retailer.',
          'Slickdeals' => 'An online coupons and deals website.',
          'Ruten' => 'A Taiwanese online auction and shopping website.',
          'Haber7' => 'Turkish news Website.',
          'Entertainment Weekly' => 'Entertainment new and video clips.',
          'Orkut' => 'Google social networking site.',
          'Gothere' => 'Navigation app for finding directions and places in Singapore.',
          'Zomato' => 'Online restaraunt database.',
          'NeoGAF' => 'Internet forum based around video games.',
          'Betclic' => 'Online gambling site.',
          'Southern Living' => 'Guide to Southern culture, recipes and travel.',
          'Qatar University' => 'Qatar University in Doha.',
          'LiveJasmin' => 'Adult content videos.',
          'Gazprom Media' => 'Russian media group comprises television, radio, advertising, movie theaters and etc.',
          'Seznam' => 'Web portal and search engine in the Czech Republic.',
          'Ad Redirector' => 'Ad service.',
          'JetBrains' => 'A collection of IDEs for different programming languages and frameworks.',
          'Baydin' => 'Gmail productivity app.',
          'Hurriyet' => 'Turkish news Website.',
          'AppNeta' => 'Web application performance metrics and analytics.',
          'EL PAIS' => 'Spanish daily newspaper portal.',
          'ADNStream' => 'Spanish video streaming site.',
          'Putlocker' => 'Online file hosting service.',
          'MOG' => 'Paid subscription online music service with streaming capability.',
          'Syncplicity' => 'Data synch service.',
          'RuTracker' => 'Russian torrent site.',
          'Genieo' => 'Web portal adware site.',
          'FileServe' => 'File hosting and sharing service.',
          'MyHeritage' => 'Family oriented social networking service.',
          'Viadeo' => 'Business focused social network.',
          'Woolik' => 'Analytics and search engine boosting.',
          'Slashdot' => 'Technology related news sharing site.',
          'WebMD' => 'Health information service.',
          'ImpressCoJp' => 'General impress.co.jp website traffic.',
          'Yandex AppMetrica' => 'Yandex analytics.',
          'Yahoo! Games' => 'Yahoo entertainment portal.',
          'Hatena Blog' => 'Internet services company in Japan.',
          'Fingta' => 'Web Services, Malware and Ads.',
          'Turner Broadcasting System' => 'Content provider for branded television network.',
          'Yandex Maps' => 'Online maps provided by Yandex.',
          'Wondershare' => 'Offers Video Software, PDF Tools, PC Utilities for Mac and Win users.',
          'Vuze' => 'Java based BitTorrent client.',
          'Merriam-Webster' => 'Online dictionary and thesaurus.',
          'OnClick' => 'Browser redirector.',
          'Intermarkets' => 'Sales management firm for Advertising.',
          'Brothersoft' => 'Free software download site.',
          'Mojang' => 'Video game developer and publisher.',
          'Fluent' => 'Marketing and analytics.',
          'Image Venue' => 'Free image hosting site.',
          'BitDefender' => 'BitDefender Antivirus/Security software download and updates.',
          'Dangdang' => 'Chinese general E-commerce company.',
          'Drudge Report' => 'News aggregator.',
          'Justin.tv' => 'Live streaming video platform.',
          'Amazon Ads System' => 'Amazon Ad services.',
          'MobileCore' => 'Mobile ad and media service.',
          'PHP' => 'Scripting language for developing server based web applications.',
          'GO.com' => 'Web portal.',
          'Enet' => 'Web portal for Chinese-speaking IT workers.',
          'Weather.com' => 'Weather Channel web portal.',
          'Clip Converter' => 'Free online video converter application.',
          'C-SPAN' => 'Cable-Satellite Public Affairs Network - Non-profit cable television.',
          'OnLive' => 'Online gaming portal.',
          'Bootstrap CDN' => 'Free and public content delivery network.',
          'Quill Corporation' => 'Mail-order office supply retailer.',
          'WarLight' => 'Online game like Risk.',
          'JonDo' => 'Anonymous surfing proxy and traffic generated by it.',
          'TRUSTe' => 'Online security service.',
          'Usenet' => 'A worldwide distributed Internet discussion forum.',
          'Inspectlet' => 'Website informatics and analytics.',
          'Eksi sozluk' => 'Turkish online dictionary.',
          'Niantic Labs' => 'Makers of popular augmented reality games Pokemon Go and Ingress.',
          'Milliyet' => 'Turkish daily newspaper published in Istanbul.',
          'CNNIC' => 'China Internet Network Infromation Center is reponsible for handling domain name registrations.',
          'GearBest' => 'Platform for user feedbacks, suggestions, promotions and giveaways.',
          'Clash Royale' => 'A web and mobile-based game spun off from Clash of Clans.',
          'RayFile' => 'Free file hosting site.',
          'GREE Games' => 'A Japanese social network and mobile gaming site.',
          'oo.com.au' => 'Australian and New Zealand online department store.',
          'EarthCam' => 'Network of live cameras in public places around the world.',
          'Suning' => 'Chinese retailer company.',
          'PBS' => 'Official website for Public Broadcasting Service, an American television network.',
          'CollegeHumor' => 'Site that presents humorous videos and media.',
          'Roku' => 'Device that streams internet video and audio to a TV.',
          'Qzone' => 'Chinese social networking site.',
          'Flixster' => 'A movie-based social networking site allowing users to share ratings and recommendations. Available Facebook app.',
          'Pokemon Go' => 'A popular mobile augmented reality game.',
          'Google Analytics' => 'Google service that tracks and generates detailed web statistics.',
          'Blip.tv' => 'Online video streaming site for web series.',
          'skyZIP' => 'Browser extenstion that uses various techniques to speed web browsing.',
          'SiteAdvisor' => 'Service that reports on the safety of web sites.',
          'SlideRocket' => 'Cloud based presentation software.',
          'SpankBang' => 'Adult videos.',
          'CTV' => 'Canadian Television network.',
          'WiZiQ' => 'Online learning tool meant to provide a virtual classroom environment.',
          'Viber' => 'Smartphone app that allows for free phone calls and text messages.',
          'ITV' => 'Streaming video provider.',
          'IMzog' => 'Adult videos.',
          'Blokus' => 'Online spatial strategy board game.',
          'GamerCom' => 'An internet forum for video games, comics, animation in taiwan.',
          'PopCap Games' => 'Online games website.',
          'ICICI Bank' => 'Indian multinational banking and financial services company.',
          'AZLyrics' => 'Website for sharing and cataloging song lyric transcriptions.',
          'SaveFrom' => 'Software that allows you to download files and videos from almost all popular video sharing networks.',
          'Mixi' => 'Japanese social blogging site.',
          'Slither' => 'Multiplayer browser game.',
          'Instructure' => 'Online portal for teaching and learning.',
          'Hello' => 'Hello is a social networking service.',
          'Coc Coc' => 'Vietnamese search engine and advertising platform.',
          'SoundHound' => 'Music search and audio hands-free app.',
          'Facebook Apps' => 'Any facebook add on, generally games, puzzles, gifts, classifieds.',
          'WooMe' => 'Online service in which users meet and interact through video chat.',
          'Boomerang' => 'Gmail send and receive scheduling.',
          'C3 Metrics' => 'Visiting websites that use C3 Metrics to deliver advertisements.',
          'Snapdeal' => 'Indian e-commerce company.',
          'Likes' => 'Entertainment website with dynamic content.',
          'Yandex Email' => 'Webmail provided by Yandex.',
          'DoubleVerify' => 'Verifies Online advertisements.',
          'UEFA' => 'European Football league.',
          'Babytree' => 'Website with resources and shopping for expectant mothers.',
          'The Xinhuanet' => 'Chinese official website for the news agency Xinhua.',
          'Olx.pl' => 'Platform to connect local people to buy, sell or exchange used goods and services through their mobile phone or on the web.',
          'Caijing' => 'Chinese independant news resource.',
          'Eastday' => 'Chinese news portal.',
          'Megashare' => 'File hosting and sharing service. Distinct from Megashares.',
          'NOAA' => 'Ocean and Atmospheric research agency.',
          'Sahibinden' => 'An online classifieds and shopping platform.',
          'Supercell' => 'Web-based game publisher.',
          'SAP HostControl' => 'SAP Host Control Agent protocol used for viewing logs and traces of a remote host.',
          'Vlingo' => 'Voice recognition and processing app for smartphones.',
          'Adobe Connect' => 'Online meeting and collaboration system.',
          'WeatherLink' => 'Site for networking of internet-capable weather devices.',
          'Apple Trailers' => 'Portal for quicktime motion picture trailers.',
          'Veoh' => 'Internet television and video sharing service.',
          'Advanced Hosters' => 'Content delivery network.',
          'FFFFOUND!' => 'Site for sharing found images from around the web.',
          'Destructoid' => 'An independent blog focused on video games.',
          'Movieclips' => 'Streaming video site for movie clips.',
          'I Waste So Much Time' => 'Funny photos and videos around the world.',
          'CPX Interactive' => 'Web advertisement services.',
          'Coral CDN' => 'Content distribution network.',
          'Sports Authority' => 'Sporting goods retailer.',
          'Openload' => 'Movies online.',
          'Frozenway' => 'VPN for bypassing firewalls.',
          'Gfycat' => 'User-generated short video hosting company.',
          'xda-developers' => 'Large online community of smartphone and tablet enthusiasts and developers.',
          'AMMYY' => 'Remote access software.',
          'Ouoio.io' => 'URL shortening service where you can shorten you links to make money from it.',
          'eRecht24' => 'Russian Web portal for all legal related information.',
          'XING' => 'Business focused social network.',
          'Zillow' => 'Online portal for Real Estate.',
          'Tokbox' => 'Video and voice messaging for eBuddy using RTMP.',
          'Ppomppu' => 'South Korean news/blogs portal.',
          'Subscene' => 'Provides subtitles in more than 50 languages.',
          'DirectREV' => 'Real-time digital ad marketplace to connects publishers with agencies and ad networks.',
          'adSage' => 'Advertisement site.',
          'Pathview' => 'An AppNeta performance metric tool.',
          'Tabelog' => 'Search/rank restaurants in Japan.',
          'Douyu' => 'Chinese portal for live video games.',
          'TuneIn' => 'Online Radio station.',
          'ETtoday' => 'Chinese online news portal.',
          'Daum Blog' => 'Daum blogging app.',
          'RedOrbit' => 'Provides information about Science, Space, Technology and health related news.',
          'Nico Nico Douga' => 'Japanese video streaming and sharing site.',
          'MSN' => 'Portal for news, video, and other content.',
          'InQuest Technologies' => 'Cloud based business automation service.',
          'Shopify' => 'eCommerce Web based Platform.',
          'Kongregate' => 'Website for hosting and playing games.',
          'Telenav' => 'Smartphone GPS app.',
          'East Money' => 'Chinese financial news portal.',
          'Scribol' => 'Online magazine covering bizarre and eclectic news on the internet.',
          'BuzzHand' => 'Content creation site for articles and collaboration.',
          'Uploaded' => 'Cloud storage and backup.',
          'iFunny' => 'Aggregator of humorous and interesting memes.',
          'WeatherBug' => 'Windows weather application.',
          'BV! Media' => 'Advertisement site.',
          'Yandex Money' => 'Financial and stock market news from Yandex.',
          'TVonline.cc' => 'Web portal agregating most TV shows/series.',
          'Cnblogs' => 'Chinese discussion forum for programmers.',
          'Me2day' => 'South Korean based social networking service.',
          'GIPHY' => 'Online database & search engine for animated GIF files.',
          'Kaspersky' => 'Kaspersky Antivirus/Security software download and updates.',
          'MyWay' => 'Adware and spyware, categorized as an internet browser hijacker.',
          'easyMule' => 'Open-Source P2P software.',
          'Localytics' => 'Mobile application analytics.',
          'dl.free.fr' => 'French based file hosting service.',
          'Pchome' => 'Computer and electronics retailer.',
          'Raging Bull' => 'Financial message board.',
          '5by5 Radio' => 'Online live and recorded talk shows.',
          'Eve Online' => 'Science fiction multi player online game.',
          'Globo' => 'Mass media group of Latin America, founded in Rio de Janeiro.',
          'Chinauma' => 'Advertisement site.',
          'GSMArena' => 'Web site providing information about mobile phones.',
          'Xnxx' => 'Adult Videos.',
          'Youdao Dictionary' => 'A chinese dictionary, available online and offline.',
          'Google Play Music' => 'Google cloud music storage and streaming.',
          'PartyPoker' => 'Web based poker.',
          'ExtraTorrent' => 'A BitTorrent network.',
          'Pogo' => 'Online games.',
          'Shorte' => 'URL shortener company that pays for clicks.',
          'Autohome.com.cn' => 'Chinese website targetted for automotive related information.',
          'MetaCrawler' => 'Metasearch engine that combines results from various popular search engines.',
          'LiteCoin' => 'A cryptopgraphic currency similar to BitCoin which requires lighter-weight resources to mine.',
          'DocuSign' => 'Secure electronic document signing.',
          'Edmunds.com' => 'General automotive information website.',
          'Addicting Games' => 'Website for flash games.',
          'BRSRVR' => 'A content delivery network.',
          'OkeZone' => 'Web site delivering the latest news in Indonesia.',
          'GameSpot' => 'Video game previews/reviews/news website.',
          'Sberbank of Russia' => 'A state-owned Russian banking and financial services company.',
          'Cvent' => 'Event registration software.',
          'Cricbuzz.com' => 'Online site to provide live Cricket updates.',
          'Upornia' => 'Adult content videos.',
          'ReImage' => 'Online computer repair.',
          'Digikala' => 'Online shopping and review forum from Iran.',
          'CheapStuff' => 'Aggregates best deals.',
          'OptMD' => 'Web advertisement services.',
          'Mister Wong' => 'European social bookmarking service.',
          'Multiupload' => 'Aggregator site for upload sites such as Megaupload, Filesonic, etc.',
          'Nokia' => 'Official site for Nokia.',
          'Betternet' => 'A VPN tunneling app.',
          'Rapidgator' => 'File hosting site.',
          'Commission Junction' => 'Web advertisement services.',
          'eBay Watch' => 'Watching an item on eBay.',
          'GAMERSKY' => 'Entertainment media that focuses on stand-alone games.',
          'CK101' => 'Chinese Internet forum.',
          'Diply' => 'Social news and entertainment with trending contents.',
          'FrostWire' => 'Open source client for BitTorrent.',
          'AVG' => 'AVG Antivirus/Security software download and updates.',
          'Voyages-sncf.com' => 'Travel agency website.',
          'Code42' => 'Enterprise data management and security software.',
          'TripIt' => 'Cloud based travel planner.',
          'iAd' => 'Web advertisement services.',
          'Maxymiser' => 'Advertising and marketing platform.',
          'Asana' => 'Collboration service.',
          'Gantter' => 'Online project management resource.',
          'TruuConfessions' => 'Online community for Confessions.',
          'Aili' => 'Chinese web portal for news and reviews about fashion.',
          'Gawker' => 'Online blog based around media news and gossip.',
          'SpiderOak' => 'Cloud storage and backup.',
          'Google Safebrowsing' => 'Website blacklisting service.',
          'Giganews' => 'A popular Usenet/newsgroup service provider.',
          'FreeStreams' => 'Online Movies, Radio and Games.',
          'Collabedit' => 'Online collaborative code editor which allows multiple users to modify/view code together.',
          'Bitauto' => 'Marketing and advertising service for Chinese auto industry.',
          'Asus' => 'Manufacturer of PCs and PC components.',
          'K9 Web Protection' => 'Security and Malware protection.',
          'Friendster' => 'Social networking site.',
          'ShowDocument' => 'Web application that allows users to collaborate on and review documents in real time.',
          'Avira Download/Update' => 'Avira Antivirus/Security software download and updates.',
          'AcFun' => 'Video sharing site.',
          'H&M' => 'Website of a clothing-retail company.',
          'RoadRunner' => 'Web Portal for entertainment and sports news update.',
          'Qatar Living' => 'Guide about living in Qatar.',
          'Ifeng.com' => 'Chinese webportal from Phoenix New media.',
          'Gulf Times' => 'Daily Newspaper published by GPPC Doha, Qatar.',
          'Crunchyroll' => 'Video streaming site specializing in Japanese animation.',
          'NY Daily News' => 'News portal.',
          'Glide' => 'Cross-platform web desktop that allows for file sharing between different computers and mobile devices.',
          'HowardForums' => 'Cellular phone forums.',
          'Quote.com' => 'Financial research and trading website.',
          'it168' => 'Chinese social media website.',
          'BillDesk' => 'Online payment consolidation site.',
          'Windows Live Hotmail' => 'Microsoft\'s free web-based email service.',
          'Spinrilla' => 'Free hip hop mixed tape downloads.',
          'David Jones' => 'High-end Australian department store.',
          'ABS-CBN' => 'Phillipines-based news.',
          'BuzzFeed' => 'News portal.',
          'Ubuntu Update Manager' => 'Update manager.',
          'Argos' => 'British online retailer of appliances, hardware, and other goods.',
          'ShopAtHome' => 'An online coupons and deals website.',
          'Kugou' => 'Peer-to-peer music.',
          'ExoClick' => 'Barcelona based advertising company for both advertisers and publishers.',
          'Po.st' => 'Social sharing platform.',
          'I2P' => 'Invisible Internet Protocol, an anonymous p2p network.',
          'ekantipur' => 'Kantipur online news portal.',
          'TinyPic' => 'Photo and video sharing service.',
          'Middle East Broadcasting Center' => 'Web site of Arabic private free-to-air satellite broadcasting company.',
          'Slingbox Media' => 'Streaming media via Slingbox.',
          'Trello' => 'Collaboration tool that organizes projects into boards.',
          'Silverlight' => 'Microsoft rich internet application framework.',
          'folkd' => 'Social bookmarking and social news website.',
          'Jungle Disk' => 'Cloud storage and backup.',
          'deviantART' => 'Online community focused around artwork.',
          'FileHost.ro' => 'Romanian File sharing service.',
          'detikcom' => 'Indonesian online news portal.',
          'HOLACOM' => 'Spanish news Website.',
          'HubSpot' => 'Developer/Marketer of software products for inbound marketing and sales.',
          'SO.com' => 'Chinese internet search engine.',
          'Yandex Market' => 'Yandex shopping.',
          'NATO' => 'Web portal for NATO.',
          'Barneys New York' => 'Luxury retail department store.',
          'Ci123' => 'Chinese marketing and ad service.',
          'FRIV' => 'Free online gaming site.',
          'ABC' => 'Web Portal for television network.',
          'GISMETEO' => 'Website providing wheather forecasts for different areas in Russia.',
          'PopUrls' => 'Website that aggregates headlines from various popular social news sites and portals.',
          'People Of Walmart' => 'Website for Walmart customer posted photos.',
          'Ninite' => 'A tool that manages installation and upgrading of apps.',
          'RarBG' => 'Website provides torrent files and magnet links to facilitate peer-to-peer file sharing using the BitTorrent protocol.',
          'Toshiba' => 'Manufacturer of computers and electronics.',
          'PrivateHomeClips' => 'Adult videos.',
          'Digg' => 'News discussion site.',
          'CiteULike' => 'Social bookmarking-esque site for scholarly papers and references.',
          'ShopStyle' => 'Fashion search engine which links to various retailers.',
          'Theme Forest' => 'An Envato marketplace for themes and skins.',
          'Nokia Store' => 'Nokia App store.',
          'BRCDN' => 'A content delivery network.',
          'Backpack' => 'Business focused information management and social networking.',
          'Caraytech' => 'Advertisement site.',
          'FlyProxy' => 'Anonymous proxy service.',
          'Sabah' => 'Turkish news website.',
          'Elmogaz' => 'Egyptian online news portal.',
          'Bilibili' => 'Chinese site for uploading and discussing anime.',
          'Coupa' => 'Procurement software.',
          'Tinychat' => 'Web chat service with both instant messaging and video chat.',
          'Backpage.com' => 'Free classified ads.',
          'wer-kennt-wen' => 'German social network.',
          'Qatar Government' => 'Qatar Government website.',
          'Dainik Bhaskar' => 'Hindi online news portal.',
          'Getscreen.me' => 'Remote Desktop Access. Cloud-based software for administration, technical support and remote work.',
          'DMM' => 'Japan-based e-commerce portal for purchasing goods and services like e-books, games, VOD, 3D priting.',
          'KBS' => 'Korean Broadcasting Syste, radio station.',
          'Anghami' => 'Music streaming site.',
          'Soribada' => 'Peer-to-peer portal and MP3 shop.',
          'Google Play Books' => 'Google ebook reader.',
          'Lucidchart' => 'Web analytics services.',
          'ScienceDirect' => 'A website which provides subscription-based access to a large databas of scientific and medical research.',
          'DINGIT.TV' => 'Sports highlights and online game portal.',
          'Legacy.com' => 'Online Obituaries.',
          'Sina' => 'A Chinese internet company that produces microblogging and social networking apps.',
          'eBuddy' => 'Web chat client.',
          'Clicksgear' => 'Suspicious Adware.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_350",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Tinychat
	{ 0, 1013, 'tinychat.com' },
	--TransferBigFiles.com
	{ 0, 1015, 'transferbigfiles.com' },
	--WooMe
	{ 0, 1025, 'woome.com' },
	--MOG
	{ 0, 1041, 'mog.com' },
	--MyHeritage
	{ 0, 1072, 'myheritage.com' },
	--Dangdang
	{ 0, 1074, 'dangdang.com' },
	--xda-developers
	{ 0, 1078, 'xda-developers.com' },
	--NeoGAF
	{ 0, 1080, 'neogaf.com' },
	--Movieclips
	{ 0, 1084, 'movieclips.com' },
	--Adobe Connect
	{ 0, 1124, 'meet.adobeconnect.com' },
	--MetaCrawler
	{ 0, 1132, 'metacrawler.com' },
	--Digg
	{ 0, 117, 'digg.com' },
	--Apple Trailers
	{ 0, 1194, 'trailers.apple.com' },
	--Brothersoft
	{ 0, 1210, 'brothersoft.com' },
	--Enet
	{ 0, 1212, 'enet.com.cn' },
	--ExtraTorrent
	{ 0, 1214, 'extratorrent.com' },
	--Image Venue
	{ 0, 1217, 'imagevenue.com' },
	--Multiupload
	{ 0, 1220, 'multiupload.com' },
	--Putlocker
	{ 0, 1224, 'putlocker.com' },
	--Raging Bull
	{ 0, 1225, 'ragingbull.com' },
	--Theme Forest
	{ 0, 1227, 'themeforest.net' },
	--Google Play Books
	{ 0, 1230, 'books.google.com' },
	--Google Play Music
	{ 0, 1231, 'music.youtube.com' },
	--Silverlight
	{ 0, 1302, 'silverlight.net' },
	--GO.com
	{ 0, 1304, 'go.com' },
	--OnLive
	{ 0, 1305, 'onlive.com' },
	--Ad Marvel
	{ 0, 1308, 'map.admarvel.com' },
	--Greystripe
	--{ 0, 1318, 'greystripe.com' },
	--iAd
	{ 0, 1319, 'advertising.apple.com' },
	--eBay Search
	{ 0, 134, 'shop.ebay.com' },
	--eBay Watch
	{ 0, 135, 'cgi1.ebay.com' },
	--eBuddy
	{ 0, 136, 'ebuddy.com' },
	--Weather.com
	{ 0, 1367, 'weather.com' },
	--OptMD
	{ 0, 1372, 'optmd.com' },
	--RoadRunner
	{ 0, 1386, 'rr.com' },
	--Drudge Report
	{ 0, 1387, 'drudgereport.com' },
	--ABC
	{ 0, 1389, 'abcnews.go.com' },
	--Ubuntu Update Manager
	{ 0, 1409, 'archive.ubuntu.com' },
	--NATO
	{ 0, 1418, 'nato.int' },
	--NOAA
	{ 0, 1420, 'noaa.gov' },
	--WeatherBug
	{ 0, 1421, 'weather.weatherbug.com' },
	--Google Adsense
	{ 0, 1424, 'googlesyndication.com' },
	--Localytics
	{ 0, 1426, 'localytics.com' },
	--CPX Interactive
	{ 0, 1457, 'cpxinteractive.com' },
	--Zillow
	{ 0, 1480, 'zillow.com' },
	--ShopAtHome
	{ 0, 1487, 'shopathome.com' },
	--Facebook Apps
	{ 0, 149, 'apps.facebook.com' },
	--Commission Junction
	{ 0, 1492, 'cj.com' },
	--Backpage.com
	{ 0, 1494, 'backpage.com' },
	--Fark
	{ 0, 150, 'fark.com' },
	--WebMD
	{ 0, 1502, 'webmd.com' },
	--Trulia
	{ 0, 1503, 'trulia.com' },
	--Slickdeals
	{ 0, 1504, 'slickdeals.net' },
	--BuzzFeed
	{ 0, 1508, 'buzzfeed.com' },
	--NY Daily News
	{ 0, 1517, 'nydailynews.com' },
	--Legacy.com
	{ 0, 1524, 'legacy.com' },
	--Flixster
	{ 0, 160, 'flixster.com' },
	--Aili
	{ 0, 1615, 'aili.com' },
	--The Xinhuanet
	{ 0, 1628, 'xinhuanet.com' },
	--Giganews
	{ 0, 175, 'giganews.com' },
	--Nokia
	{ 0, 1769, 'nokia.com' },
	--Nokia Store
	{ 0, 1771, 'static.store.ovi.com' },
	--PBS
	{ 0, 1772, 'pbs.org' },
	--TRUSTe
	{ 0, 1775, 'truste.com' },
	--DoubleVerify
	{ 0, 1776, 'doubleverify.com' },
	--People Of Walmart
	{ 0, 1783, 'peopleofwalmart.com' },
	--TruuConfessions
	{ 0, 1789, 'truuconfessions.com' },
	--Amazon Ads System
	{ 0, 1804, 's.amazon-adsystem.com' },
	--TuneIn
	{ 0, 1810, 'tunein.com' },
	--RedOrbit
	{ 0, 1989, 'redorbit.com' },
	--I Waste So Much Time
	{ 0, 2001, 'iwastesomuchtime.com' },
	--K9 Web Protection
	{ 0, 2013, 'k9webprotection.com' },
	--Roku
	{ 0, 2034, 'roku.com' },
	--Windows Live Hotmail
	{ 0, 205, 'hotmail.com' },
	--Turner Broadcasting System
	{ 0, 2057, 'turner.com' },
	--Po.st
	{ 0, 2060, 'po.st' },
	--CheapStuff
	{ 0, 2061, 'cheapstuff.com' },
	--FreeStreams
	{ 0, 2063, 'freestreams.com' },
	--Intermarkets
	{ 0, 2068, 'intermarkets.net' },
	--C-SPAN
	{ 0, 2074, 'c-span.org' },
	--LiteCoin
	{ 0, 2084, 'litecoin.org' },
	--Entertainment Weekly
	{ 0, 2095, 'ew.com' },
	--Auditude
	--{ 0, 2129, 'connect.auditude.com' },
	--iFunny
	{ 0, 2133, 'ifunny.com' },
	--Telenav
	{ 0, 2134, 'telenav.com' },
	--Vlingo
	{ 0, 2135, 'vlingo.com' },
	--Crunchyroll
	{ 0, 2138, 'crunchyroll.com' },
	--Asus
	{ 0, 2145, 'asus.com' },
	--Toshiba
	{ 0, 2148, 'toshiba.com' },
	--Ensighten
	{ 0, 2157, 'nexus.ensighten.com' },
	--Maxymiser
	{ 0, 2158, 'service.maxymiser.net' },
	--CollegeHumor
	{ 0, 2164, 'collegehumor.com' },
	--WeatherLink
	{ 0, 2195, 'weatherlink.com' },
	--FrostWire
	{ 0, 2214, 'frostwire.com' },
	--5by5 Radio
	{ 0, 2218, '5by5.tv' },
	--PHP
	{ 0, 2230, 'php.net' },
	--FFFFOUND!
	{ 0, 2255, 'ffffound.com' },
	--AudioDocumentary.org
	{ 0, 2271, 'audiodocumentary.org' },
	--Pchome
	{ 0, 2350, 'pchome.net' },
	--Quote.com
	{ 0, 2353, 'quote.com' },
	--Hupu
	{ 0, 2356, 'hupu.com' },
	--Viber
	{ 0, 2367, 'viber.com' },
	--ADNStream
	{ 0, 2370, 'adnstream.com' },
	--it168
	{ 0, 2373, 'it168.com' },
	--Tokbox
	{ 0, 2400, 'tokbox.com' },
	--Mediaplex
	--{ 0, 2407, 'mediaplex.com' },
	--Southern Living
	{ 0, 2427, 'southernliving.com' },
	--Coupa
	{ 0, 2429, 'coupa.com' },
	--KBS
	{ 0, 2435, 'kbs.co.kr' },
	--BRSRVR
	{ 0, 2457, 'cdn.brsrvr.com' },
	--BRCDN
	{ 0, 2459, 'p1.brcdn.com' },
	--Kaspersky
	{ 0, 248, 'usa.kaspersky.com' },
	--East Money
	{ 0, 2481, 'eastmoney.com' },
	--Blokus
	{ 0, 2482, 'blokus.com' },
	--Chinauma
	{ 0, 2490, 'chinauma.com' },
	--adSage
	{ 0, 2491, 'adsage.com' },
	--Proclivity
	{ 0, 2533, 'proclivitysystems.com' },
	--Kugou
	{ 0, 256, 'static.kugou.com' },
	--Caraytech
	{ 0, 2573, 'caraytech.com.ar' },
	--BV! Media
	{ 0, 2576, 'bvmedia.ca' },
	--Undertone
	{ 0, 2583, 'undertone.com' },
	--HowardForums
	{ 0, 2598, 'howardforums.com' },
	--EarthCam
	{ 0, 2604, 'earthcam.com' },
	--SopCast
	{ 0, 2628, 'sopcast.com' },
	--Genieo
	{ 0, 2686, 'genieo.com' },
	--TVonline.cc
	{ 0, 2735, 'tvonline.cc' },
	--CTV
	{ 0, 2750, 'ctv.ca' },
	--Gazprom Media
	{ 0, 2760, 'gazprom-media.com' },
	--Merriam-Webster
	{ 0, 2789, 'merriam-webster.com' },
	--RayFile
	{ 0, 2823, 'rayfile.com' },
	--Glide
	{ 0, 2827, 'glideos.com' },
	--FlyProxy
	{ 0, 2837, 'flyproxy.com.ipaddress.com' },
	--Coral CDN
	{ 0, 2838, 'coralcdn.org' },
	--Autohome.com.cn
	{ 0, 2852, 'autohome.com.cn' },
	--Ifeng.com
	{ 0, 2856, 'ifeng.com' },
	--FileHost.ro
	{ 0, 2884, 'filehost.ro' },
	--AMMYY
	{ 0, 2894, 'ammyy.com' },
	--JonDo
	{ 0, 2947, 'anonymous-proxy-servers.net' },
	--Mixi
	{ 0, 295, 'mixi.jp' },
	--MSDN
	{ 0, 304, 'msdn.microsoft.com' },
	--MSN
	{ 0, 308, 'msn.com' },
	--Orkut
	{ 0, 356, 'orkut.com' },
	--PartyPoker
	{ 0, 360, 'partypoker.com' },
	--Fluent
	{ 0, 3658, 'fluentmobile.com' },
	--Woolik
	{ 0, 3674, 'woolik.com' },
	--Sina
	{ 0, 3675, 'sina.com' },
	--Betclic
	{ 0, 3703, 'en.betclic.com' },
	--easyMule
	{ 0, 3728, 'easymule.com' },
	--AppNeta
	{ 0, 3742, 'appneta.com' },
	--Pathview
	{ 0, 3752, 'pathviewcloud.com' },
	--Slingbox Media
	{ 0, 3753, 'sso.slingmedia.com' },
	--C3 Metrics
	{ 0, 3819, 'c3metrics.com' },
	--Bootstrap CDN
	{ 0, 3822, 'bootstrapcdn.com' },
	--GREE Games
	{ 0, 3852, 'gree.net' },
	--ITV
	{ 0, 3859, 'tom.itv.com' },
	{ 0, 3859, 'itv.com' },
	--Code42
	{ 0, 3877, 'code42.com' },
	--CrashPlan
	{ 0, 3878, 'crashplan.com' },
	--Asana
	{ 0, 3950, 'asana.com' },
	--Baydin
	{ 0, 3951, 'baydin.com' },
	--Boomerang
	{ 0, 3952, 'boomeranggmail.com' },
	--Cloudsponge
	{ 0, 3953, 'cloudsponge.com' },
	--Cvent
	{ 0, 3954, 'cvent.com' },
	--DocuSign
	{ 0, 3955, 'docusign.com' },
	--Gantter
	{ 0, 3957, 'gantter.com' },
	--InQuest Technologies
	{ 0, 3959, 'inquesttechnologies.com' },
	--Inspectlet
	{ 0, 3960, 'inspectlet.com' },
	--Lucidchart
	{ 0, 3961, 'lucidchart.com' },
	--SlideRocket
	{ 0, 3963, 'sliderocket.com' },
	{ 0, 3963, 'clearslide.com' },
	--TripIt
	{ 0, 3965, 'tripit.com' },
	--UEFA
	{ 0, 3966, 'uefa.com' },
	--WarLight
	{ 0, 3967, 'warlight.net' },
	--Zomato
	{ 0, 3968, 'zomato.com' },
	--JetBrains
	{ 0, 3981, 'jetbrains.com' },
	--Youdao Dictionary
	{ 0, 3982, 'youdao.com' },
	--Eve Online
	{ 0, 4004, 'eveonline.com' },
	{ 0, 4004, 'secure.eveonline.com' },
	--Mojang
	{ 0, 4006, 'mojang.com' },
	--CloudApp
	{ 0, 4021, 'my.cl.ly' },
	--Rapidgator
	{ 0, 4024, 'rapidgator.net' },
	--Syncplicity
	{ 0, 4027, 'syncplicity.com' },
	--I2P
	{ 0, 4033, 'geti2p.net' },
	--Jungle Disk
	{ 0, 4034, 'jungledisk.com' },
	--Ninite
	{ 0, 4035, 'ninite.com' },
	--SpiderOak
	{ 0, 4036, 'spideroak.com' },
	--Uploaded
	{ 0, 4037, 'uploaded.net' },
	--Wondershare
	{ 0, 4038, 'wondershare.net' },
	--Spinrilla
	{ 0, 4044, 'spinrilla.com' },
	--skyZIP
	{ 0, 4047, 'skyzip.de' },
	--Daum Blog
	{ 0, 4052, 'blog.daum.net' },
	--Yandex AppMetrica
	{ 0, 4059, 'appmetrica.yandex.com' },
	--Yandex Email
	{ 0, 4061, 'mail.yandex.com' },
	--Yandex Maps
	{ 0, 4062, 'suggest-maps.yandex.ru' },
	--Yandex Money
	{ 0, 4063, 'money.yandex.com' },
	--Yandex Market
	{ 0, 4064, 'market.yandex.ru' },
	--Yandex Translate
	{ 0, 4066, 'translate.yandex.com' },
	--MobileCore
	{ 0, 4086, 'mobilecore.com' },
	--Betternet
	{ 0, 4092, 'betternet.co' },
	--Frozenway
	{ 0, 4096, 'frozendo.com' },
	--Supercell
	{ 0, 4097, 'supercell.com' },
	--Clash Royale
	{ 0, 4098, 'clashroyale.com' },
	--SAP HostControl
	{ 0, 410, 'sap.com' },
	--SoundHound
	{ 0, 4102, 'soundhound.com' },
	--Anghami
	{ 0, 4103, 'anghami.com' },
	--Niantic Labs
	{ 0, 4104, 'nianticlabs.com' },
	--Pokemon Go
	{ 0, 4105, 'pokemongo.com' },
	--Hello
	{ 0, 4108, 'hello.com' },
	--Gothere
	{ 0, 4131, 'gothere.sg' },
	--BlueJeans
	{ 0, 4151, 'bluejeans.com' },
	--Openload
	{ 0, 4159, 'openload.co' },
	--ABS-CBN
	{ 0, 4168, 'abs-cbn.com' },
	--AcFun
	{ 0, 4169, 'acfun.cn' },
	--Ad Redirector
	{ 0, 4170, 'adexchangeprediction.com' },
	--Advanced Hosters
	{ 0, 4171, 'ahcdn.com' },
	--asos
	{ 0, 4174, 'asos.com' },
	--AZLyrics
	{ 0, 4176, 'azlyrics.com' },
	--Babytree
	{ 0, 4177, 'babytree.com' },
	--Qatar Government
	{ 0, 4183, 'portal.www.gov.qa' },
	--Qatar Living
	{ 0, 4184, 'qatarliving.com' },
	--Qatar University
	{ 0, 4185, 'qu.edu.qa' },
	--RarBG
	{ 0, 4190, 'rarbg.to' },
	--RedTube
	{ 0, 4191, 'redtube.com' },
	--ReImage
	{ 0, 4192, 'reimageplus.com' },
	--Ruten
	{ 0, 4196, 'ruten.com.tw' },
	--RuTracker
	{ 0, 4197, 'rutracker.org' },
	--Sabah
	{ 0, 4198, 'sabah.com.tr' },
	--Sahibinden
	{ 0, 4199, 'sahibinden.com' },
	--SaveFrom
	{ 0, 4200, 'en.savefrom.net' },
	--Sberbank of Russia
	{ 0, 4201, 'sberbank.ru' },
	--ScienceDirect
	{ 0, 4203, 'sciencedirect.com' },
	--Middle East Broadcasting Center
	{ 0, 4206, 'mbc.net' },
	--Milliyet
	{ 0, 4210, 'milliyet.com.tr' },
	--MyWay
	{ 0, 4211, 'hp.myway.com' },
	--OkeZone
	{ 0, 4220, 'okezone.com' },
	--Olx.pl
	{ 0, 4221, 'olx.pl' },
	--OnClick
	{ 0, 4222, 'onclkds.com' },
	--Ouoio.io
	{ 0, 4227, 'ouo.io' },
	--Ppomppu
	{ 0, 4237, 'ppomppu.co.kr' },
	--PrivateHomeClips
	{ 0, 4238, 'hclips.com' },
	--Bilibili
	{ 0, 4240, 'bilibili.com' },
	--BillDesk
	{ 0, 4241, 'billdesk.com' },
	--Bitauto
	{ 0, 4242, 'bitauto.com' },
	--Blasting News
	{ 0, 4243, 'blastingnews.com' },
	--BuzzHand
	{ 0, 4248, 'buzzhand.com' },
	--Caijing
	{ 0, 4249, 'caijing.com.cn' },
	--CCTV.com
	{ 0, 4251, 'cctv.com' },
	--Ci123
	{ 0, 4254, 'ci123.com' },
	--Fingta
	{ 0, 4255, 'rudateblue2.fingta.com' },
	--Freepik
	{ 0, 4256, 'freepik.com' },
	--FRIV
	{ 0, 4257, 'friv.com' },
	--GamerCom
	{ 0, 4258, 'gamer.com.tw' },
	--GAMERSKY
	{ 0, 4259, 'gamersky.com' },
	--GearBest
	{ 0, 4260, 'gearbest.com' },
	--Gfycat
	{ 0, 4261, 'gfycat.com' },
	--GIPHY
	{ 0, 4262, 'giphy.com' },
	--GISMETEO
	{ 0, 4263, 'gismeteo.ru' },
	--Globo
	{ 0, 4264, 'globo.com' },
	--GSMArena
	{ 0, 4265, 'gsmarena.com' },
	--Gulf Times
	{ 0, 4266, 'gulf-times.com' },
	--Haber7
	{ 0, 4267, 'haber7.com' },
	--HandyCafe
	{ 0, 4268, 'handycafe.com' },
	--Hatena Blog
	{ 0, 4269, 'hatenablog.com' },
	--HDFC Bank
	{ 0, 4270, 'hdfcbank.com' },
	--H&M
	{ 0, 4271, 'hm.com' },
	--HOLACOM
	{ 0, 4272, 'hola.com' },
	--Huanqiu
	{ 0, 4273, 'huanqiu.com' },
	--HubSpot
	{ 0, 4274, 'hubspot.com' },
	--Hurriyet
	{ 0, 4275, 'hurriyet.com.tr' },
	--ICICI Bank
	{ 0, 4276, 'icicibank.com' },
	--ImpressCoJp
	{ 0, 4277, 'impress.co.jp' },
	--IMzog
	{ 0, 4278, 'imzog.com' },
	--Scribol
	{ 0, 4279, 'scribol.com' },
	--Seznam
	{ 0, 4281, 'onas.seznam.cz' },
	--Shopify
	{ 0, 4282, 'shopify.com' },
	--Shorte
	{ 0, 4283, 'shorte.st' },
	--SiteAdvisor
	{ 0, 4284, 'siteadvisor.com' },
	--Slither
	{ 0, 4285, 'slither.io' },
	--Snapdeal
	{ 0, 4286, 'snapdeal.com' },
	--SO.com
	{ 0, 4287, 'so.com' },
	--SpankBang
	{ 0, 4289, 'spankbang.com' },
	--Subscene
	{ 0, 4290, 'subscene.com' },
	--Suning
	{ 0, 4291, 'suning.com' },
	--Tabelog
	{ 0, 4292, 'tabelog.com' },
	--Trello
	{ 0, 4300, 'trello.com' },
	--CK101
	{ 0, 4305, 'ck101.com' },
	--Clicksgear
	{ 0, 4306, 'clicksgear.com' },
	--Clip Converter
	{ 0, 4307, 'clipconverter.cc' },
	--Cnblogs
	{ 0, 4308, 'cnblogs.com' },
	--CNNIC
	{ 0, 4309, 'cnnic.cn' },
	{ 0, 4309, 'cnnic.com.cn' },
	--Coc Coc
	{ 0, 4311, 'coccoc.com' },
	--Conservative Tribune
	--{ 0, 4312, 'conservativetribune.com' },
	--Cricbuzz.com
	{ 0, 4313, 'cricbuzz.com' },
	--Dainik Bhaskar
	{ 0, 4315, 'bhaskar.com' },
	--detikcom
	{ 0, 4317, 'detik.com' },
	--Digikala
	{ 0, 4319, 'digikala.com' },
	--Slingbox
	{ 0, 432, 'slingmedia.com' },
	--DINGIT.TV
	{ 0, 4320, 'dingit.tv' },
	--Diply
	{ 0, 4321, 'diply.com' },
	--DirectREV
	{ 0, 4322, 'directrev.com' },
	--DMM
	{ 0, 4323, 'dmm.com' },
	--Douyu
	{ 0, 4324, 'douyu.com' },
	--Eastday
	{ 0, 4325, 'eastday.com' },
	--ekantipur
	{ 0, 4326, 'ekantipur.com' },
	--Eksi sozluk
	{ 0, 4327, 'eksisozluk.com' },
	--Elmogaz
	{ 0, 4328, 'elmogaz.com' },
	--EL PAIS
	{ 0, 4329, 'elpais.com' },
	--ETtoday
	{ 0, 4330, 'ettoday.net' },
	--ExoClick
	{ 0, 4331, 'exoclick.com' },
	--Instructure
	{ 0, 4332, 'instructure.com' },
	--Likes
	{ 0, 4349, 'likes.com' },
	--LiveJasmin
	{ 0, 4351, 'livejasmin.com' },
	--Upornia
	{ 0, 4355, 'upornia.com' },
	--Xnxx
	{ 0, 4378, 'xnxx.com' },
	--AVG
	{ 0, 44, 'avg.com' },
	--Avira Download/Update
	{ 0, 45, 'avira.com' },
	--Getscreen.me
	{ 0, 4660, 'getscreen.me' },
	--Backpack
	{ 0, 48, 'backpackit.com' },
	--Usenet
	{ 0, 487, 'usenetserver.com' },
	--Vuze
	{ 0, 497, 'vuze.com' },
	--Yahoo! Games
	{ 0, 522, 'games.yahoo.com' },
	--Addicting Games
	{ 0, 540, 'addictinggames.com' },
	--Argos
	{ 0, 554, 'argos.co.uk' },
	--Barneys New York
	{ 0, 562, 'barneys.com' },
	--Blip.tv
	{ 0, 574, 'blip.tv' },
	--BitDefender
	{ 0, 59, 'bitdefender.com' },
	--Collabedit
	{ 0, 592, 'collabedit.com' },
	--David Jones
	{ 0, 601, 'davidjones.com.au' },
	--Deals Direct
	{ 0, 604, 'dealsdirect.com.au' },
	--Destructoid
	{ 0, 607, 'destructoid.com' },
	--deviantART
	{ 0, 608, 'deviantart.com' },
	--Edmunds.com
	{ 0, 622, 'edmunds.com' },
	--Friendster
	{ 0, 642, 'friendster.com' },
	--GameSpot
	{ 0, 648, 'gamespot.com' },
	--Gawker
	{ 0, 652, 'gawker.com' },
	--Google Analytics
	{ 0, 660, 'google-analytics.com' },
	--Google Safebrowsing
	{ 0, 665, 'safebrowsing-cache.google.com' },
	--Kongregate
	{ 0, 705, 'kongregate.com' },
	--Nico Nico Douga
	{ 0, 762, 'nicovideo.jp' },
	--oo.com.au
	{ 0, 770, 'oo.com.au' },
	--Pogo
	{ 0, 787, 'pogo.com' },
	--PopCap Games
	{ 0, 789, 'popcap.com' },
	--PopUrls
	{ 0, 790, 'popurls.com' },
	--Quill Corporation
	{ 0, 797, 'quill.com' },
	--Qzone
	{ 0, 799, 'qzone.qq.com' },
	--ShopStyle
	{ 0, 828, 'shopstyle.com' },
	--ShowDocument
	{ 0, 831, 'showdocument.co' },
	--Slashdot
	{ 0, 834, 'slashdot.com' },
	--Soribada
	{ 0, 840, 'soribada.com' },
	--Sports Authority
	{ 0, 842, 'sportsauthority.com' },
	--TinyPic
	{ 0, 873, 'tinypic.com' },
	--Urban Outfitters
	{ 0, 883, 'urbanoutfitters.com' },
	--Veoh
	{ 0, 889, 'veoh.com' },
	--Viadeo
	{ 0, 891, 'viadeo.com' },
	--wer-kennt-wen
	{ 0, 908, 'wer-kennt-wen.de' },
	--WiZiQ
	{ 0, 914, 'wiziq.com' },
	--XING
	{ 0, 922, 'xing.com' },
	--Hightail
	{ 0, 928, 'yousendit.com' },
	--Netflix stream
	{ 0, 939, 'nflxvideo.net' },
	--DivShare
	{ 0, 966, 'divshare.com' },
	--dl.free.fr
	{ 0, 967, 'dl.free.fr' },
	--FileServe
	{ 0, 973, 'fileserve.com' },
	--folkd
	{ 0, 975, 'folkd.com' },
	--CiteULike
	{ 0, 979, 'citeulike.org' },
	--Justin.tv
	{ 0, 988, 'justin.tv' },
	--Me2day
	{ 0, 992, 'me2day.net' },
	--Megashare
	{ 0, 993, 'megashare.com' },
	--Neopets
	{ 0, 996, 'neopets.com' },
}
gSSLCnamePatternList = {
	--Tinychat
	{ 0, 1013, 'tinychat.com' },
	--TransferBigFiles.com
	{ 0, 1015, 'transferbigfiles.com' },
	--WooMe
	{ 0, 1025, 'woome.com' },
	--MOG
	{ 0, 1041, 'mog.com' },
	--MyHeritage
	{ 0, 1072, 'myheritage.com' },
	--Dangdang
	{ 0, 1074, 'dangdang.com' },
	--xda-developers
	{ 0, 1078, 'xda-developers.com' },
	--NeoGAF
	{ 0, 1080, 'neogaf.com' },
	--Movieclips
	{ 0, 1084, 'movieclips.com' },
	--Adobe Connect
	{ 0, 1124, 'meet.adobeconnect.com' },
	--MetaCrawler
	{ 0, 1132, 'metacrawler.com' },
	--Digg
	{ 0, 117, 'digg.com' },
	--Apple Trailers
	{ 0, 1194, 'trailers.apple.com' },
	--Brothersoft
	{ 0, 1210, 'brothersoft.com' },
	--Enet
	{ 0, 1212, 'enet.com.cn' },
	--ExtraTorrent
	{ 0, 1214, 'extratorrent.com' },
	--Image Venue
	{ 0, 1217, 'imagevenue.com' },
	--Multiupload
	{ 0, 1220, 'multiupload.com' },
	--Putlocker
	{ 0, 1224, 'putlocker.com' },
	--Raging Bull
	{ 0, 1225, 'ragingbull.com' },
	--Theme Forest
	{ 0, 1227, 'themeforest.net' },
	--Google Play Books
	{ 0, 1230, 'books.google.com' },
	--Google Play Music
	{ 0, 1231, 'music.youtube.com' },
	--Silverlight
	{ 0, 1302, 'silverlight.net' },
	--GO.com
	{ 0, 1304, 'go.com' },
	--OnLive
	{ 0, 1305, 'onlive.com' },
	--Ad Marvel
	{ 0, 1308, 'map.admarvel.com' },
	--Greystripe
	--{ 0, 1318, 'greystripe.com' },
	--iAd
	{ 0, 1319, 'advertising.apple.com' },
	--eBay Search
	{ 0, 134, 'shop.ebay.com' },
	--eBay Watch
	{ 0, 135, 'cgi1.ebay.com' },
	--eBuddy
	{ 0, 136, 'ebuddy.com' },
	--Weather.com
	{ 0, 1367, 'weather.com' },
	--OptMD
	{ 0, 1372, 'optmd.com' },
	--RoadRunner
	{ 0, 1386, 'rr.com' },
	--Drudge Report
	{ 0, 1387, 'drudgereport.com' },
	--ABC
	{ 0, 1389, 'abcnews.go.com' },
	--Ubuntu Update Manager
	{ 0, 1409, 'archive.ubuntu.com' },
	--NATO
	{ 0, 1418, 'nato.int' },
	--NOAA
	{ 0, 1420, 'noaa.gov' },
	--WeatherBug
	{ 0, 1421, 'weather.weatherbug.com' },
	--Google Adsense
	{ 0, 1424, 'googlesyndication.com' },
	--Localytics
	{ 0, 1426, 'localytics.com' },
	--CPX Interactive
	{ 0, 1457, 'cpxinteractive.com' },
	--Zillow
	{ 0, 1480, 'zillow.com' },
	--ShopAtHome
	{ 0, 1487, 'shopathome.com' },
	--Facebook Apps
	{ 0, 149, 'apps.facebook.com' },
	--Commission Junction
	{ 0, 1492, 'cj.com' },
	--Backpage.com
	{ 0, 1494, 'backpage.com' },
	--Fark
	{ 0, 150, 'fark.com' },
	--WebMD
	{ 0, 1502, 'webmd.com' },
	--Trulia
	{ 0, 1503, 'trulia.com' },
	--Slickdeals
	{ 0, 1504, 'slickdeals.net' },
	--BuzzFeed
	{ 0, 1508, 'buzzfeed.com' },
	--NY Daily News
	{ 0, 1517, 'nydailynews.com' },
	--Legacy.com
	{ 0, 1524, 'legacy.com' },
	--Flixster
	{ 0, 160, 'flixster.com' },
	--Aili
	{ 0, 1615, 'aili.com' },
	--The Xinhuanet
	{ 0, 1628, 'xinhuanet.com' },
	--OsiriX
	{ 0, 1677, 'osirix-viewer.com' },
	--Giganews
	{ 0, 175, 'giganews.com' },
	--Nokia
	{ 0, 1769, 'nokia.com' },
	--Nokia Store
	{ 0, 1771, 'static.store.ovi.com' },
	--PBS
	{ 0, 1772, 'pbs.org' },
	--TRUSTe
	{ 0, 1775, 'truste.com' },
	--DoubleVerify
	{ 0, 1776, 'doubleverify.com' },
	--People Of Walmart
	{ 0, 1783, 'peopleofwalmart.com' },
	--TruuConfessions
	{ 0, 1789, 'truuconfessions.com' },
	--Amazon Ads System
	{ 0, 1804, 's.amazon-adsystem.com' },
	--TuneIn
	{ 0, 1810, 'tunein.com' },
	--RedOrbit
	{ 0, 1989, 'redorbit.com' },
	--I Waste So Much Time
	{ 0, 2001, 'iwastesomuchtime.com' },
	--K9 Web Protection
	{ 0, 2013, 'k9webprotection.com' },
	--Roku
	{ 0, 2034, 'roku.com' },
	--Windows Live Hotmail
	{ 0, 205, 'hotmail.com' },
	--Po.st
	{ 0, 2060, 'po.st' },
	--CheapStuff
	{ 0, 2061, 'cheapstuff.com' },
	--FreeStreams
	{ 0, 2063, 'freestreams.com' },
	--Intermarkets
	{ 0, 2068, 'intermarkets.net' },
	--C-SPAN
	{ 0, 2074, 'c-span.org' },
	--LiteCoin
	{ 0, 2084, 'litecoin.org' },
	--Entertainment Weekly
	{ 0, 2095, 'ew.com' },
	--Auditude
	--{ 0, 2129, 'connect.auditude.com' },
	--iFunny
	{ 0, 2133, 'ifunny.com' },
	--Telenav
	{ 0, 2134, 'telenav.com' },
	--Vlingo
	{ 0, 2135, 'vlingo.com' },
	--Crunchyroll
	{ 0, 2138, 'crunchyroll.com' },
	--Asus
	{ 0, 2145, 'asus.com' },
	--Toshiba
	{ 0, 2148, 'toshiba.com' },
	--Ensighten
	{ 0, 2157, 'nexus.ensighten.com' },
	--Maxymiser
	{ 0, 2158, 'service.maxymiser.net' },
	--CollegeHumor
	{ 0, 2164, 'collegehumor.com' },
	--WeatherLink
	{ 0, 2195, 'weatherlink.com' },
	--FrostWire
	{ 0, 2214, 'frostwire.com' },
	--5by5 Radio
	{ 0, 2218, '5by5.tv' },
	--PHP
	{ 0, 2230, 'php.net' },
	--FFFFOUND!
	{ 0, 2255, 'ffffound.com' },
	--AudioDocumentary.org
	{ 0, 2271, 'audiodocumentary.org' },
	--Pchome
	{ 0, 2350, 'pchome.net' },
	--Quote.com
	{ 0, 2353, 'quote.com' },
	--Hupu
	{ 0, 2356, 'hupu.com' },
	--Viber
	{ 0, 2367, 'viber.com' },
	--ADNStream
	{ 0, 2370, 'adnstream.com' },
	--it168
	{ 0, 2373, 'it168.com' },
	--Tokbox
	{ 0, 2400, 'tokbox.com' },
	--Mediaplex
	--{ 0, 2407, 'mediaplex.com' },
	--Southern Living
	{ 0, 2427, 'southernliving.com' },
	--Coupa
	{ 0, 2429, 'coupa.com' },
	--KBS
	{ 0, 2435, 'kbs.co.kr' },
	--BRSRVR
	{ 0, 2457, 'cdn.brsrvr.com' },
	--BRCDN
	{ 0, 2459, 'p1.brcdn.com' },
	--Kaspersky
	{ 0, 248, 'usa.kaspersky.com' },
	--East Money
	{ 0, 2481, 'eastmoney.com' },
	--Blokus
	{ 0, 2482, 'blokus.com' },
	--Chinauma
	{ 0, 2490, 'chinauma.com' },
	--adSage
	{ 0, 2491, 'adsage.com' },
	--Kugou
	{ 0, 256, 'static.kugou.com' },
	--Caraytech
	{ 0, 2573, 'caraytech.com.ar' },
	--BV! Media
	{ 0, 2576, 'bvmedia.ca' },
	--Undertone
	{ 0, 2583, 'undertone.com' },
	--HowardForums
	{ 0, 2598, 'howardforums.com' },
	--EarthCam
	{ 0, 2604, 'earthcam.com' },
	--SopCast
	{ 0, 2628, 'sopcast.com' },
	--Genieo
	{ 0, 2686, 'genieo.com' },
	--TVonline.cc
	{ 0, 2735, 'tvonline.cc' },
	--CTV
	{ 0, 2750, 'ctv.ca' },
	--Gazprom Media
	{ 0, 2760, 'gazprom-media.com' },
	--eRecht24
	{ 0, 2785, 'e-recht24.de' },
	--Merriam-Webster
	{ 0, 2789, 'merriam-webster.com' },
	--RayFile
	{ 0, 2823, 'rayfile.com' },
	--Glide
	{ 0, 2827, 'glideos.com' },
	--FlyProxy
	{ 0, 2837, 'flyproxy.com.ipaddress.com' },
	--Coral CDN
	{ 0, 2838, 'coralcdn.org' },
	--Autohome.com.cn
	{ 0, 2852, 'autohome.com.cn' },
	--Ifeng.com
	{ 0, 2856, 'ifeng.com' },
	--FileHost.ro
	{ 0, 2884, 'filehost.ro' },
	--AMMYY
	{ 0, 2894, 'ammyy.com' },
	--JonDo
	{ 0, 2947, 'anonymous-proxy-servers.net' },
	--Mixi
	{ 0, 295, 'mixi.jp' },
	--MSDN
	{ 0, 304, 'msdn.microsoft.com' },
	--MSN
	{ 0, 308, 'msn.com' },
	--Orkut
	{ 0, 356, 'orkut.com' },
	--PartyPoker
	{ 0, 360, 'partypoker.com' },
	--Fluent
	{ 0, 3658, 'fluentmobile.com' },
	--Woolik
	{ 0, 3674, 'woolik.com' },
	--Sina
	{ 0, 3675, 'sina.com' },
	--Betclic
	{ 0, 3703, 'en.betclic.com' },
	--easyMule
	{ 0, 3728, 'easymule.com' },
	--AppNeta
	{ 0, 3742, 'appneta.com' },
	--Pathview
	{ 0, 3752, 'pathviewcloud.com' },
	--Slingbox Media
	{ 0, 3753, 'sso.slingmedia.com' },
	--C3 Metrics
	{ 0, 3819, 'c3metrics.com' },
	--Bootstrap CDN
	{ 0, 3822, 'bootstrapcdn.com' },
	--GREE Games
	{ 0, 3852, 'gree.net' },
	--ITV
	{ 0, 3859, 'tom.itv.com' },
	{ 0, 3859, 'itv.com' },
	--Code42
	{ 0, 3877, 'code42.com' },
	--CrashPlan
	{ 0, 3878, 'crashplan.com' },
	--Asana
	{ 0, 3950, 'asana.com' },
	--Baydin
	{ 0, 3951, 'baydin.com' },
	--Boomerang
	{ 0, 3952, 'boomeranggmail.com' },
	--Cloudsponge
	{ 0, 3953, 'cloudsponge.com' },
	--Cvent
	{ 0, 3954, 'cvent.com' },
	--DocuSign
	{ 0, 3955, 'docusign.com' },
	--Gantter
	{ 0, 3957, 'gantter.com' },
	--InQuest Technologies
	{ 0, 3959, 'inquesttechnologies.com' },
	--Inspectlet
	{ 0, 3960, 'inspectlet.com' },
	--Lucidchart
	{ 0, 3961, 'lucidchart.com' },
	--SlideRocket
	{ 0, 3963, 'sliderocket.com' },
	{ 0, 3963, 'clearslide.com' },
	--TripIt
	{ 0, 3965, 'tripit.com' },
	--UEFA
	{ 0, 3966, 'uefa.com' },
	--WarLight
	{ 0, 3967, 'warlight.net' },
	--Zomato
	{ 0, 3968, 'zomato.com' },
	--JetBrains
	{ 0, 3981, 'jetbrains.com' },
	--Youdao Dictionary
	{ 0, 3982, 'youdao.com' },
	--Eve Online
	{ 0, 4004, 'eveonline.com' },
	{ 0, 4004, 'secure.eveonline.com' },
	--Mojang
	{ 0, 4006, 'mojang.com' },
	--CloudApp
	{ 0, 4021, 'my.cl.ly' },
	--Rapidgator
	{ 0, 4024, 'rapidgator.net' },
	--Syncplicity
	{ 0, 4027, 'syncplicity.com' },
	--I2P
	{ 0, 4033, 'geti2p.net' },
	--Jungle Disk
	{ 0, 4034, 'jungledisk.com' },
	--Ninite
	{ 0, 4035, 'ninite.com' },
	--SpiderOak
	{ 0, 4036, 'spideroak.com' },
	--Uploaded
	{ 0, 4037, 'uploaded.net' },
	--Wondershare
	{ 0, 4038, 'wondershare.net' },
	--Spinrilla
	{ 0, 4044, 'spinrilla.com' },
	--skyZIP
	{ 0, 4047, 'skyzip.de' },
	--Daum Blog
	{ 0, 4052, 'blog.daum.net' },
	--Yandex AppMetrica
	{ 0, 4059, 'appmetrica.yandex.com' },
	--Yandex Email
	{ 0, 4061, 'mail.yandex.com' },
	--Yandex Maps
	{ 0, 4062, 'suggest-maps.yandex.ru' },
	--Yandex Money
	{ 0, 4063, 'money.yandex.com' },
	--Yandex Market
	{ 0, 4064, 'market.yandex.ru' },
	--Yandex Translate
	{ 0, 4066, 'translate.yandex.com' },
	--MobileCore
	{ 0, 4086, 'mobilecore.com' },
	--Betternet
	{ 0, 4092, 'betternet.co' },
	--Frozenway
	{ 0, 4096, 'frozendo.com' },
	--Supercell
	{ 0, 4097, 'supercell.com' },
	--Clash Royale
	{ 0, 4098, 'clashroyale.com' },
	--SAP HostControl
	{ 0, 410, 'sap.com' },
	--SoundHound
	{ 0, 4102, 'soundhound.com' },
	--Anghami
	{ 0, 4103, 'anghami.com' },
	--Niantic Labs
	{ 0, 4104, 'nianticlabs.com' },
	--Pokemon Go
	{ 0, 4105, 'pokemongo.com' },
	--Hello
	{ 0, 4108, 'hello.com' },
	--Gothere
	{ 0, 4131, 'gothere.sg' },
	--BlueJeans
	{ 0, 4151, 'bluejeans.com' },
	--Openload
	{ 0, 4159, 'openload.co' },
	--ABS-CBN
	{ 0, 4168, 'abs-cbn.com' },
	--AcFun
	{ 0, 4169, 'acfun.cn' },
	--Ad Redirector
	{ 0, 4170, 'adexchangeprediction.com' },
	--Advanced Hosters
	{ 0, 4171, 'ahcdn.com' },
	--asos
	{ 0, 4174, 'asos.com' },
	--AZLyrics
	{ 0, 4176, 'azlyrics.com' },
	--Babytree
	{ 0, 4177, 'babytree.com' },
	--Qatar Government
	{ 0, 4183, 'portal.www.gov.qa' },
	--Qatar Living
	{ 0, 4184, 'qatarliving.com' },
	--Qatar University
	{ 0, 4185, 'qu.edu.qa' },
	--RarBG
	{ 0, 4190, 'rarbg.to' },
	--RedTube
	{ 0, 4191, 'redtube.com' },
	--ReImage
	{ 0, 4192, 'reimageplus.com' },
	--Ruten
	{ 0, 4196, 'ruten.com.tw' },
	--RuTracker
	{ 0, 4197, 'rutracker.org' },
	--Sabah
	{ 0, 4198, 'sabah.com.tr' },
	--Sahibinden
	{ 0, 4199, 'sahibinden.com' },
	--SaveFrom
	{ 0, 4200, 'en.savefrom.net' },
	--Sberbank of Russia
	{ 0, 4201, 'sberbank.ru' },
	--ScienceDirect
	{ 0, 4203, 'sciencedirect.com' },
	--Middle East Broadcasting Center
	{ 0, 4206, 'mbc.net' },
	--Milliyet
	{ 0, 4210, 'milliyet.com.tr' },
	--MyWay
	{ 0, 4211, 'hp.myway.com' },
	--OkeZone
	{ 0, 4220, 'okezone.com' },
	--Olx.pl
	{ 0, 4221, 'olx.pl' },
	--OnClick
	{ 0, 4222, 'onclkds.com' },
	--Ouoio.io
	{ 0, 4227, 'ouo.io' },
	--Ppomppu
	{ 0, 4237, 'ppomppu.co.kr' },
	--PrivateHomeClips
	{ 0, 4238, 'hclips.com' },
	--Bilibili
	{ 0, 4240, 'bilibili.com' },
	--BillDesk
	{ 0, 4241, 'billdesk.com' },
	--Bitauto
	{ 0, 4242, 'bitauto.com' },
	--Blasting News
	{ 0, 4243, 'blastingnews.com' },
	--BuzzHand
	{ 0, 4248, 'buzzhand.com' },
	--Caijing
	{ 0, 4249, 'caijing.com.cn' },
	--CCTV.com
	{ 0, 4251, 'cctv.com' },
	--Ci123
	{ 0, 4254, 'ci123.com' },
	--Fingta
	{ 0, 4255, 'Rudateblue2.fingta.com' },
	--Freepik
	{ 0, 4256, 'freepik.com' },
	--FRIV
	{ 0, 4257, 'friv.com' },
	--GamerCom
	{ 0, 4258, 'gamer.com.tw' },
	--GAMERSKY
	{ 0, 4259, 'gamersky.com' },
	--GearBest
	{ 0, 4260, 'gearbest.com' },
	--Gfycat
	{ 0, 4261, 'gfycat.com' },
	--GIPHY
	{ 0, 4262, 'giphy.com' },
	--GISMETEO
	{ 0, 4263, 'gismeteo.ru' },
	--Globo
	{ 0, 4264, 'globo.com' },
	--GSMArena
	{ 0, 4265, 'gsmarena.com' },
	--Gulf Times
	{ 0, 4266, 'gulf-times.com' },
	--Haber7
	{ 0, 4267, 'haber7.com' },
	--HandyCafe
	{ 0, 4268, 'handycafe.com' },
	--Hatena Blog
	{ 0, 4269, 'hatenablog.com' },
	--HDFC Bank
	{ 0, 4270, 'hdfcbank.com' },
	--H&M
	{ 0, 4271, 'hm.com' },
	--HOLACOM
	{ 0, 4272, 'hola.com' },
	--Huanqiu
	{ 0, 4273, 'huanqiu.com' },
	--HubSpot
	{ 0, 4274, 'hubspot.com' },
	--Hurriyet
	{ 0, 4275, 'hurriyet.com.tr' },
	--ICICI Bank
	{ 0, 4276, 'icicibank.com' },
	--ImpressCoJp
	{ 0, 4277, 'impress.co.jp' },
	--IMzog
	{ 0, 4278, 'imzog.com' },
	--Scribol
	{ 0, 4279, 'scribol.com' },
	--Seznam
	{ 0, 4281, 'onas.seznam.cz' },
	--Shopify
	{ 0, 4282, 'shopify.com' },
	--Shorte
	{ 0, 4283, 'shorte.st' },
	--SiteAdvisor
	{ 0, 4284, 'siteadvisor.com' },
	--Slither
	{ 0, 4285, 'slither.io' },
	--Snapdeal
	{ 0, 4286, 'snapdeal.com' },
	--SO.com
	{ 0, 4287, 'so.com' },
	--SpankBang
	{ 0, 4289, 'spankbang.com' },
	--Subscene
	{ 0, 4290, 'subscene.com' },
	--Suning
	{ 0, 4291, 'suning.com' },
	--Tabelog
	{ 0, 4292, 'tabelog.com' },
	--Trello
	{ 0, 4300, 'trello.com' },
	--CK101
	{ 0, 4305, 'ck101.com' },
	--Clicksgear
	{ 0, 4306, 'clicksgear.com' },
	--Clip Converter
	{ 0, 4307, 'clipconverter.cc' },
	--Cnblogs
	{ 0, 4308, 'cnblogs.com' },
	--CNNIC
	{ 0, 4309, 'cnnic.cn' },
	{ 0, 4309, 'cnnic.com.cn' },
	--Coc Coc
	{ 0, 4311, 'coccoc.com' },
	--Conservative Tribune
	--{ 0, 4312, 'conservativetribune.com' },
	--Cricbuzz.com
	{ 0, 4313, 'cricbuzz.com' },
	--Dainik Bhaskar
	{ 0, 4315, 'bhaskar.com' },
	--detikcom
	{ 0, 4317, 'detik.com' },
	--Digikala
	{ 0, 4319, 'digikala.com' },
	--Slingbox
	{ 0, 432, 'slingmedia.com' },
	--DINGIT.TV
	{ 0, 4320, 'dingit.tv' },
	--Diply
	{ 0, 4321, 'diply.com' },
	--DirectREV
	{ 0, 4322, 'directrev.com' },
	--DMM
	{ 0, 4323, 'dmm.com' },
	--Douyu
	{ 0, 4324, 'douyu.com' },
	--Eastday
	{ 0, 4325, 'eastday.com' },
	--ekantipur
	{ 0, 4326, 'ekantipur.com' },
	--Eksi sozluk
	{ 0, 4327, 'eksisozluk.com' },
	--Elmogaz
	{ 0, 4328, 'elmogaz.com' },
	--EL PAIS
	{ 0, 4329, 'elpais.com' },
	--ETtoday
	{ 0, 4330, 'ettoday.net' },
	--ExoClick
	{ 0, 4331, 'exoclick.com' },
	--Instructure
	{ 0, 4332, 'instructure.com' },
	--Likes
	{ 0, 4349, 'likes.com' },
	--LiveJasmin
	{ 0, 4351, 'livejasmin.com' },
	--Upornia
	{ 0, 4355, 'upornia.com' },
	--Xnxx
	{ 0, 4378, 'xnxx.com' },
	--AVG
	{ 0, 44, 'avg.com' },
	--Avira Download/Update
	{ 0, 45, 'avira.com' },
	--Getscreen.me
	{ 0, 4660, 'getscreen.me' },
	--Backpack
	{ 0, 48, 'backpackit.com' },
	--Usenet
	{ 0, 487, 'usenetserver.com' },
	--Vuze
	{ 0, 497, 'vuze.com' },
	--Yahoo! Games
	{ 0, 522, 'games.yahoo.com' },
	--Addicting Games
	{ 0, 540, 'addictinggames.com' },
	--Argos
	{ 0, 554, 'argos.co.uk' },
	--Barneys New York
	{ 0, 562, 'barneys.com' },
	--Blip.tv
	{ 0, 574, 'blip.tv' },
	--BitDefender
	{ 0, 59, 'bitdefender.com' },
	--Collabedit
	{ 0, 592, 'collabedit.com' },
	--David Jones
	{ 0, 601, 'davidjones.com.au' },
	--Deals Direct
	{ 0, 604, 'dealsdirect.com.au' },
	--Destructoid
	{ 0, 607, 'destructoid.com' },
	--deviantART
	{ 0, 608, 'deviantart.com' },
	--Edmunds.com
	{ 0, 622, 'edmunds.com' },
	--Friendster
	{ 0, 642, 'friendster.com' },
	--GameSpot
	{ 0, 648, 'gamespot.com' },
	--Gawker
	{ 0, 652, 'gawker.com' },
	--Google Analytics
	{ 0, 660, 'google-analytics.com' },
	--Google Safebrowsing
	{ 0, 665, 'safebrowsing-cache.google.com' },
	--Kongregate
	{ 0, 705, 'kongregate.com' },
	--Nico Nico Douga
	{ 0, 762, 'nicovideo.jp' },
	--oo.com.au
	{ 0, 770, 'oo.com.au' },
	--Pogo
	{ 0, 787, 'pogo.com' },
	--PopCap Games
	{ 0, 789, 'popcap.com' },
	--PopUrls
	{ 0, 790, 'popurls.com' },
	--Quill Corporation
	{ 0, 797, 'quill.com' },
	--Qzone
	{ 0, 799, 'qzone.qq.com' },
	--ShopStyle
	{ 0, 828, 'shopstyle.com' },
	--ShowDocument
	{ 0, 831, 'showdocument.co' },
	--Slashdot
	{ 0, 834, 'slashdot.com' },
	--Soribada
	{ 0, 840, 'soribada.com' },
	--Sports Authority
	{ 0, 842, 'sportsauthority.com' },
	--TinyPic
	{ 0, 873, 'tinypic.com' },
	--Urban Outfitters
	{ 0, 883, 'urbanoutfitters.com' },
	--Veoh
	{ 0, 889, 'veoh.com' },
	--Viadeo
	{ 0, 891, 'viadeo.com' },
	--Voyages-sncf.com
	{ 0, 899, 'voyages-sncf.com' },
	--wer-kennt-wen
	{ 0, 908, 'wer-kennt-wen.de' },
	--WiZiQ
	{ 0, 914, 'wiziq.com' },
	--XING
	{ 0, 922, 'xing.com' },
	--Hightail
	{ 0, 928, 'yousendit.com' },
	--Netflix stream
	{ 0, 939, 'nflxvideo.net' },
	--DivShare
	{ 0, 966, 'divshare.com' },
	--dl.free.fr
	{ 0, 967, 'dl.free.fr' },
	--FileServe
	{ 0, 973, 'fileserve.com' },
	--folkd
	{ 0, 975, 'folkd.com' },
	--CiteULike
	{ 0, 979, 'citeulike.org' },
	--Justin.tv
	{ 0, 988, 'justin.tv' },
	--Me2day
	{ 0, 992, 'me2day.net' },
	--Megashare
	{ 0, 993, 'megashare.com' },
	--Neopets
	{ 0, 996, 'neopets.com' },
	--Mister Wong
	{ 0, 999, 'mister-wong.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end


    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3])
        end
    end

    return gDetector
end

function DetectorClean()
end
