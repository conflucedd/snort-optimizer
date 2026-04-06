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
detection_name: SSL Group "334 part3"
version: 25
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'HostGator' => 'Web hosting portal.',
          'AddThis' => 'Social bookmarking service.',
          'SHOWTIME ANYTIME' => 'On-Demand access for Showtime series, movies and other entertainments.',
          'Mobile Theory' => 'Advertisement site.',
          'The Free Dictionary' => 'Online dictionary aggregator.',
          'Yahoo! Douga' => 'Yahoo! Japan video streaming site.',
          'MTv' => 'Official website for MTv.',
          'Napster' => 'Audio streaming and MP3 store.',
          'Kay Jewelers' => 'Retail jeweller.',
          'Technorati' => 'Search engine for blogs.',
          'Tianya' => 'Chinese forum for blogging, microblogging and photo album services.',
          'In.com' => 'Entertainment news and media.',
          'CarMax' => 'New and used car retailer.',
          'Tencent Video' => 'Tencent streaming video.',
          'Weather Underground' => 'Weather web portal.',
          'The Independent' => 'Online portal for UK based and world news.',
          'PubNub' => 'Cloud-based system for apps that require data to be pushed in real time.',
          'Qriocity' => 'Streaming music and video on demand service from Sony.',
          'TwitPic' => 'Site for posting and sharing photos and videos on twitter.',
          'FogBugz' => 'Web-based project management and bug tracking system.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'NextBus' => 'Live updates on public transit system.',
          'The Baltimore Sun' => 'Offcial website for the daily newspaper covering local and regional events in Baltimore.',
          'Fab.com' => 'E-commerce for all articles.',
          'Voyages-sncf.com' => 'Travel agency website.',
          'SUPERAntiSpyware' => 'Antivirus / antimalware application.',
          'VTunnel' => 'Web based proxy service.',
          'POLITICO.com' => 'News portal.',
          'Publishers Clearing House' => 'Online marketing company.',
          'Gizmodo' => 'Blogs about design and technology.',
          'Stitcher' => 'Internet radio for news and talk shows.',
          'Hulu' => 'Video streaming.',
          'Tinder' => 'Social Network for connecting people.',
          'Komli Media' => 'Online marketing and advertising.',
          '4399.com' => 'Chinese gaming website.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'Fiverr' => 'E-Commerce site generally for $5.',
          'BigUpload' => 'File hosting and sharing service.',
          'Eclipse Marketplace' => 'Marketplace for Eclipse application.',
          'Tickets.com' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'RitzCamera.com' => 'Photography goods and electronics retailer.',
          'Fetion' => 'Chinese instant messaging client.',
          'CafeMom' => 'Social networking site targeted towards mothers.',
          'Nike' => 'Shoe and sports apparel manufacturer.',
          'Netease' => 'Chinese web portal.',
          'Examiner.com' => 'News portal.',
          'CNBC' => 'Official website for the CNBC channel which is basically meant for Business and Financial market related news.',
          'hi5' => 'Social networking and social gaming platform.',
          'MissLee' => 'Korean Instant Messenger.',
          'Collider' => 'Movie/Television news, reviews and trailers.',
          'TypePad' => 'Blogging service website.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'Blue Nile' => 'Online jewelry and diamonds retailer.',
          'China Daily' => 'Chinese news site.',
          'Amobee' => 'Advertisement site.',
          'Viewsurf' => 'French video streaming and download site.',
          'Staples' => 'Office supply retailer.',
          'Livestream' => 'Live streaming video platform.',
          'USA Today' => 'Website for newspaper USA Today.',
          'MetaFilter' => 'Community weblog for link sharing.',
          'Newegg' => 'Computer hardware and software retailer.',
          'FileDropper' => 'File hosting and sharing service.',
          'AOL' => 'American company develops, grows and invests in brands and web sites.',
          'Taobao' => 'Chinese online auction and shopping website.',
          'NPR' => 'National Public Radio - Associates US national radio station to provide news and other programs.',
          'CTV News' => 'News channel by CTV.',
          'J.C. Penney' => 'Clothing and accessory retailer.',
          'Youku' => 'Chinese video hosting and sharing service.',
          'Wow' => 'A search engine.',
          'E! Online' => 'Online entertainment news.',
          'Investopedia' => 'A wiki focused on information related to investments.',
          'Pandora TV' => 'Pandora streaming TV service.',
          'Kotaku' => 'Video game focused blog.',
          'TV Guide' => 'Listings and schedules for television programming.',
          'Netvibes' => 'Web portal.',
          'Tesco.com' => 'General E-commerce website.',
          'Basecamp' => 'Web based project management tool.',
          '56.com' => 'Large Chinese video sharing site.',
          'OsiriX' => 'Image processing tool for DICOM images.',
          'Adblade' => 'Advertising platform.',
          'Western Digital' => 'Data storage company and hard disk drive manufacturers.',
          'Yahoo! Toolbar' => 'Yahoo!\'s browser toolbar.',
          'Cyworld' => 'South Korean social networking service.',
          'Car and Driver' => 'American automotive enthusiast news site.',
          'Patch.com' => 'Local news website.',
          'T Mobile' => 'Telecommunication and phone service provider.',
          'Adweek' => 'Marketing, Media and advertising news.',
          'QDown' => 'Korean Entertainment web portal.',
          'Bejeweled Blitz' => 'Facebook version of Bejeweled 2.',
          'CNET' => 'Tech and gadget related news, reviews, and shopping.',
          'CloudMe' => 'Web desktop service.',
          'Daily Mail' => 'Web Portal for news update.',
          'B&H Photo Video' => 'Online retailer of cameras.',
          'VKontakte' => 'Russian social networking service.',
          'EarthLink' => 'IT Solution provider for network and communications.',
          'Indiatimes' => 'Online news portal.',
          'InsightExpress' => 'Analyser for online and Mobile advertisements.',
          'FTD' => 'Floral retailer.',
          'T. Rowe Price' => 'Public investment firm.',
          'Rockstar Games' => 'Developer and Publisher of video games.',
          'PC Connection' => 'Computer and electronic products retailer.',
          'VoiceFive' => 'Advertisement site.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Naver' => 'Web portal.',
          'Ad Master' => 'Advertisement site.',
          'Jamendo' => 'Website that allows for the streaming, downloading, and uploading of free music.',
          '1-800-Flowers' => 'Online retailer of flowers and other gifts.',
          'Saks Fifth Avenue' => 'Luxury, high-end specialty store.',
          'Expedia' => 'Travel reservation website.',
          'Clarizen' => 'Work management and project management system.',
          'Kontiki' => 'Cloud based enterprise for video platform.',
          'Issuu' => 'Web based document posting and sharing service.',
          'Stack Overflow' => 'Question and Answering site for programmers.',
          'Realtor.com' => 'Web portal Real Estate.',
          'PPStream' => 'Chinese video streaming software.',
          'WorldstarHipHop' => 'Entertainment, hip hop, music videos and blogs.',
          'Searchnu' => 'Search engine.',
          'Cabal Online' => 'Online multiplayer games.',
          'Bizrate' => 'Lists best deals for online shopping.',
          'Motorola' => 'Manufacturer of mobile devices and telephony equipment.',
          'Okta' => 'An enterprise service that manages login credentials in the cloud.',
          'Goodreads' => 'Book review and cataloging.',
          'Flipkart' => 'India-based shopping site.',
          'People.com' => 'Web portal for the Weekly magazine People.',
          'Tvigle' => 'Russian Video syndication website.',
          'Hangame' => 'Korean online game portal.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'Songza' => 'Web radio and music streaming service.',
          'Aliwangwang' => 'Instant messaging.',
          'myUdutu' => 'Online course authoring tool.',
          '39.net' => 'Chinese health information web portal.',
          'Boxnet Upload SSL' => 'Online repository for documents, spreadsheet and presentations.  This app can be detected from decrypted traffic only.',
          'Times Union' => 'News local to Albany, New York.',
          'Android.com' => 'Android web site.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'Xunlei Kankan' => 'Chinese webportal for video-on-demand service.',
          'spin.de' => 'German social network and dating site.',
          'Doubleclick' => 'Web advertisement services.',
          'WDT' => 'Weather Decision Technologies, a company that provides weather nowcasting apps.',
          'Flickr Upload' => 'Online photo management and sharing.',
          'Kogan Technologies' => 'Australian retailer of consumer electronic devices.',
          'Office Depot' => 'Office supply retailer.',
          'Ameba' => 'Japanese blogging and social networking website.',
          'theCHIVE' => 'Funny photos and videos.',
          'UOL' => 'Brazilian web portal for news and entertainment.',
          'Adobe Software' => 'Adobe software and updates.',
          'Gateway' => 'Manufacturer and retailer of PCs.',
          'Joystiq' => 'Video gaming blog.',
          'Newser' => 'Online new portal.',
          'Guangming Online' => 'Chinese news site.',
          'MegaMeeting' => 'Web based conferencing platform.',
          'TripAdvisor' => 'Travel services site for information and reviews regarding travel related content.',
          'OpenBSD' => 'Open source code for security, enterprise and server.',
          'CheapOAir' => 'Travel booking and price comparison site.',
          'Ustream.tv' => 'Video streaming and sharing.',
          'MyDownloader' => 'Service for downloading files from numerous file hosting sites such as Rapidshare.',
          'Show My Weather' => 'Weather forecast site.',
          'Woot' => 'Online retailer that sells one discount product a day.',
          'Renren' => 'Chinese social networking site.',
          'Acer' => 'Manufacturer of PCs and laptops.',
          'Disqus' => 'Company which provides discussion forum features.',
          'AutoZone' => 'Automotive parts and accessories retailer.',
          'Federated Media' => 'Advertisement site.',
          'CamerasDirect.com.au' => 'Australian camera and photography gear retailer.',
          'Moat' => 'Ad search and analystics.',
          'vente-privee.com' => 'Private online shopping club focused on fashion and lifestyle products.',
          'Adobe Analytics' => 'Provides reporting, visualizations, and analysis of Customer Data that allows Customers to discover actionable insights.',
          'Ticketmaster' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'FilmOn' => 'Subscription based video on demand and TV streaming service.',
          'People\'s Daily' => 'Chinese news website.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'Washington Times' => 'Official web site for the Washington times news portal.',
          'Telecom Express' => 'Advertisement site.',
          'ClickBank' => 'Online marketplace for Digital products.',
          'LiveJournal' => 'Social blogging site.',
          'LeTV' => 'Chinese online video portal.',
          'Infusionsoft' => 'Software company providing solutions for sales and marketing.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'Capital One' => 'U.S. based bank holding company.',
          'Daum' => 'Popular South Korean web portal.',
          'Verizon' => 'Internet, TV and Phone service provider.',
          'Lord & Taylor' => 'Specialty-retail department store chain.',
          'Netlog' => 'Social networking site geared towards European youth.',
          'MovieTickets.com' => 'Webportal for advanced movie ticketing, reviews and celebrity interviews.',
          'Black & Decker Corporation' => 'Power tools, hardware, and home improvement products retailer.',
          'China News' => 'Chinese news site.',
          'Sina Video' => 'Video streaming from Chinese news/social website Sina.',
          'FORA.tv' => 'Website hosting videos of live events, lectures, and debates.',
          'Top Gear' => 'Website for the related British TV series focused on cars.',
          'TMZ' => 'Entertainment news.',
          'Filemail' => 'File hosting and sharing service.',
          'The Blaze' => 'News and Opinion website.',
          'Ad Mob' => 'Web advertisement services.',
          'RuTube' => 'Russian online video sharing service.',
          'Comedy Central' => 'Official website of Comedy Central, Television channel.',
          'Lineage' => 'Online game for multiplayer.',
          'Casale' => 'Advertisement site.',
          'The New York Times' => 'Newspaper website.',
          'Sanook.com' => 'Web portal for Entertainment purpose like games, lotery, news and music.',
          'Game Front' => 'Gaming news, reviews, cheats, and walkthroughs.',
          'StubHub' => 'Website for buying and selling tickets for sports, concerts, and other events.',
          'Menards' => 'Home improvement goods retailer.',
          'Livemocha' => 'Language learning community and platform offering free and paid language courses.',
          'Blockbuster' => 'Movie and video game rental/streaming website.',
          'wimp.com' => 'Site that provides links to viral videos.',
          '4chan' => 'Website that hosts found images and discussions on them.',
          'The Daily Beast' => 'American news reporting and opinion website.',
          'Salesforce.com Live Agent' => 'Salesforce.com\'s live chat support service.',
          'USAIP' => 'VPN software.',
          'Media Hub' => 'Samsung video store.',
          'yfrog' => 'Site for posting and sharing photos and videos on twitter.',
          'REI' => 'Outdoor sporting clothing and gear retailer.',
          'Apple sites' => 'Apple corporate websites.',
          'Conduit' => 'Online website to create community toolbar.',
          'Fancy' => 'Social media to share and buy items.',
          'Avaya' => 'Network and Communication solution provider.',
          'OkCupid' => 'Online Dating website.',
          'Wood TV8' => 'Michigan TV news network.',
          'SOUNDROP' => 'Listen to music online.',
          'PayPal' => 'E-commerce website for handling online transactions.',
          'ShowClix' => 'A full-service ticketing company.',
          'Ad Tech' => 'Advertisement site Adtech AG, part of AOL networks.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'ShopNBC' => 'General shopping website in association with it\'s related televised shopNBC broadcasts.',
          'news.com.au' => 'News site based in Australia.',
          'ESPN' => 'Online Sports news and show.',
          'Monster.com' => 'Online job search portal.',
          'Rhapsody' => 'Online streaming music service.',
          'China.com' => 'Chinese social networking site.',
          'Al Jazeera' => 'News network based in the Arab world.',
          'Web Of Trust' => 'Community-based website reputation rating tool.',
          'Vimeo' => 'Website for viewing and sharing videos.',
          'Monetate' => 'Advertisement site.',
          'Mashable' => 'News  blog website for social network and new technology.',
          'PNAS' => 'Offical journal from United States National Academy of Sciences.',
          'MGID' => 'Service provider for advertising and marketing.',
          'Discover' => 'Financial services company.',
          'ProxEasy' => 'Anonymous web based proxy service.',
          'Vanguard' => 'Investment management company.',
          'Redmine' => 'Web based bug tracking and project management tool.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'Viki' => 'Watch and upload movies, TV shows and music online.',
          'GOMTV Remote Control' => 'Mobile app that allows for remote control of GOM streaming to a television set or media player.',
          'INRIX' => 'Mobile app for Traffic related updates.',
          'Kmart' => 'Discount department store/retailer.',
          'FOX' => 'Official website for Fox entertainment.',
          'Fuyin.TV' => 'Chinese website for Christians.',
          'The Seattle Times' => 'Newspaper with a focus on the Seattle metro area.',
          'MKRU Streaming' => 'Live streaming for the Russian newspaper Moskovskij Komsomolets.',
          'OverBlog' => 'Platform to create blogs.',
          'Zol.com.cn' => 'Online website for IT professional.',
          'Phoca' => 'Software components useful for web design.',
          'Zippyshare' => 'File hosting site.',
          'QVC' => 'General shopping website in association with its related televised QVC broadcasts.',
          'SLI Systems' => 'Advertisement site.',
          'iAstrology' => 'Facebook astrology app.',
          'SpeedRunsLive' => 'Online gaming.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'Babelgum' => 'Internet TV service.',
          'Admin5' => 'Chinese directory of web admins.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'Neustar Information Services' => 'Advertisement site.',
          'BBC' => 'Web Portal for news update.',
          'NBC News' => 'NBCUniversal\'s news website.',
          'State Farm' => 'Insurance company.',
          'Yahoo!' => 'Yahoo! and it\'s online services.',
          'SFGate' => 'Bay area news portal.',
          'ESTsoft' => 'Provides software tools and online games.',
          'DCinside' => 'Internet forum for photography and Digital camera.',
          'Ad Nexus' => 'Web advertisement services.',
          'ESPN Video' => 'Video streaming on ESPN.',
          'Pastebin.com' => 'Online whiteboard application.',
          'Fileguri' => 'Korean file sharing web site.',
          'eBay Bid' => 'Bidding in an eBay Auction.',
          'Exponential Interactive' => 'Advertisement site.',
          '7digital' => 'Digital music and video delivery company.',
          'Clip2Net' => 'Yandex cloud storage that acts like a clipboard.',
          'City Sports' => 'Sporting goods and athletic apparel retailer.',
          'YY' => 'Chinese Chat application.',
          'Bloomingdales' => 'Retail department store.',
          'Swagbucks' => 'Online rewards program.',
          'Kiwoom' => 'Investment firm.',
          'LiveStrong.com' => 'Health and fitness information.',
          'GoToMyPC' => 'PC remote control software.',
          'Naver Cafe' => 'Naver forums and social networking.',
          'BitCoin' => 'Application and website for mining and exchanging BitCoins, a cryptographic currency.',
          'American Express' => 'Financial services company.',
          'Jalopnik' => 'Automotive news and information blog.',
          'Clear Channel' => 'Aggregates online radio broadcasting.',
          'IMDB' => 'Movie information, reviews and previews.',
          'TopTenREVIEWS' => 'Information, Reviews and recommendation about the product.',
          'ServiceNow' => 'Cloud storage provider.',
          'GOLF.com' => 'News, instruction and courses about Golf.',
          'Overstock.com' => 'Online discount retailer.',
          'Vonage' => 'Vonage is a VoIP company that provides telephone service via a broadband connection.',
          'NHL.com' => 'The National Hockey League official website.',
          'HootSuite' => 'Social Network management.',
          'Intuit' => 'Software company for financial and tax related services.',
          'Clubbox' => 'Korean online movie/channel/music.',
          'Travelocity' => 'Online travel agency.',
          'Pinterest' => 'Social photo sharing website.',
          'VLC Media Player' => 'Free and open source media player.',
          'Douban' => 'Chinese social networking service.',
          'Sears' => 'Department store retailer.',
          'OneDrive' => 'Microsoft cloud storage offering, successor to SkyDrive.',
          'Alibaba' => 'International trade site.',
          'Djpod' => 'A suite of tools for podcasting.',
          'Flexera Software' => 'Software tools for creating packages with compatible to cross platforms.',
          'Progressive' => 'Insurance company.',
          'WhereCoolThingsHappen' => 'Cool places and photos around the world.',
          '247 Inc.' => 'Advertisement site.',
          'Southwest Airlines' => 'Airlines service in United States.',
          'De Telegraaf' => 'Dutch daily newspaper site.',
          'REVOLVEclothing' => 'Designer clothing and accessories retailer.',
          'Nate' => 'Web portal and Search engine.',
          'Weibo' => 'Chinese microblogging site produced by Sina.',
          'Autodesk' => 'A CAD and 3D printing software company.',
          'Linux Mint' => 'Linux based Operating System.',
          'Coupons.com' => 'An online coupons and deals website.',
          'Haiku Learning Systems' => 'Online tool for teaching and learning.',
          'Game Informer' => 'Video game news, reviews, and previews website.',
          'Costco' => 'Warehouse club\'s online retail website.',
          'Wolfram Alpha' => 'Online answering for queries from the structred data.',
          'Yandex' => 'Russian search engine.',
          'Indeed' => 'The job search engine.',
          'LinkedIn Contacts' => 'LinkedIn application for networking with contacts.',
          'Wordpress' => 'An online blogging community.',
          'House of Fraser' => 'British department store.',
          'AccuWeather' => 'Weather forecasting website.',
          'Wretch' => 'Taiwanese community website.',
          'Baidu Movies' => 'Video search engine by Baidu.',
          'CDiscount' => 'French online retailer.',
          'Gaia Online' => 'Anime themed social networking and forums website.',
          'eHow' => 'Website featuring tutorials on a wide variety of subjects.',
          'Manta' => 'Provides US company profiles and information.',
          'Mister Wong' => 'European social bookmarking service.',
          'Zappos' => 'Online shoe and apparel retailer.',
          'EA Games' => 'Web portal for Electronics Arts, a video games distributor.',
          'California.gov' => 'California government official website.',
          'Lowe\'s' => 'Home improvement and appliance retailer.',
          'Softpedia' => 'Software download site.',
          'Blizzard' => 'The website for Blizzard Software, a popular PC and console game company.',
          'Skyrock' => 'Social networking site popular in France.',
          'The Escapist Magazine' => 'Online Magazine for Video game lovers.',
          'Macy\'s' => 'Department store chain.',
          'WebM Files' => 'Site for sharing videos in webm format.',
          'Rackspace' => 'Virtual and physical server hosting providers.',
          'Newsvine' => 'Community based collaborative news website.',
          'Picsearch' => 'Image search engine.',
          'Licorize' => 'Social bookmarking service.',
          'Apache Nutch' => 'Open soruce web crawler.',
          'CNET TV' => 'Videos on tech and gadget related website.',
          'Glype' => 'Web-based proxy.',
          'Dillards' => 'Retail department store.',
          'Wired.com' => 'Online magazine.',
          'ToysRUs' => 'Official website for ToyRUs, which deals with toys.',
          'Nordstrom' => 'Retail department store.',
          'Ancestry.com' => 'Online family history resource.',
          'BaiduHi' => 'Baidu instant messaging.',
          'Office 365' => 'Traffic generated by MS Office 365 applications and web services.',
          'GoToTraining' => 'Citrix GoToMeeting service focused on online training.',
          'Bejeweled Chrome Extension' => 'Bejeweled for the Chrome browser.',
          'Adtech' => 'Advertisement site.',
          'Commvault' => 'Enterprise data backup and storage management software.',
          'Jubii' => 'Web portal providing search engine, e-mail, and file sharing services.',
          'Evony' => 'Browser-based online multiplayer game.',
          'Ace Hardware Corporation' => 'Home improvement goods and hardware retailer.',
          '6.pm' => 'Discount shoes and clothing retailer.',
          'Sky.com' => 'Web portal for news.',
          'XiTi' => 'Advertising and analytics site.',
          'Lijit' => 'Advertising and analystics company.',
          'L\'equipe.fr' => 'French sports news site.',
          'Nintendo' => 'Content delivery and web traffic from Nintendo, a Japanese company.',
          '51.com' => 'Chinese social networking site.',
          'Weather.gov' => 'Weather web portal.',
          'CNN.com' => 'Turner Broadcasting System\'s news website.',
          'Baidu Yun' => 'Baidu cloud storage and P2P file transfer.',
          'Bubble Witch Saga' => 'Witch-themed, bubble-bursting Facebook game.',
          'XM Radio Online' => 'Streaming audio.',
          'The Onion' => 'Online humor and news satire site.',
          'Twitter Link Service' => 't.co, Twitter\'s URL redirect service.',
          'Drugs.com' => 'Online pharmacy.',
          'Swarovski' => 'Retailer for jewelry and other related luxury products.',
          'Cute Overload' => 'Pictures,videos and stories about Animals.',
          'Fox Sports' => 'Web Portal for Sports news update.',
          'Phanfare' => 'Subscription based photo and video sharing service.',
          'Crackle' => 'Digital network providing streaming video content.',
          'OfficeMax' => 'Office supplies retailer.',
          'Neckermann' => 'General goods online retailer.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.',
          'Reuters' => 'News portal.',
          '1&1 Internet' => 'Internet and Domain name service provider.',
          'eyeReturn' => 'Advertisement site.',
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Slacker' => 'Internet radio service.',
          'Level 3' => 'Level 3 Communications content delivery network.',
          'Mininova' => 'BitTorrent downloads website.',
          'Omegle' => 'Online chat service that pairs together strangers.',
          'Adorama' => 'Online camera retailer.',
          'InSkin Media' => 'Advertisement site.',
          'Cedexis' => 'Advertising and analytics site.',
          '2345.com' => 'Web portal.',
          'NIH' => 'National Institute of Health and Human services.',
          'CNZZ' => 'Advertisement site.',
          'Aweber' => 'Email marketing Service.',
          '2channel' => 'Japan based Internet forum.',
          'Intel' => 'Computer chip builder.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'wetpaint entertainment' => 'Television related news and media.',
          'Proxistore' => 'Advertising and analytics site.',
          'Aptean' => 'Enterprise software company.',
          'Forbes' => 'Website for Forbes, a business news magazine.',
          'AdNetwork.net' => 'Ad Portal.',
          'Baidu' => 'Chinese Search engine.',
          'Tomatopang' => 'Korean Peer to Peer file-sharing application.',
          'Etao' => 'Chinese web portal.',
          'Goal' => 'Football news and statistics.',
          'Schwab' => 'Brokerage and banking company.',
          'WTOP' => 'Official web site for WTOP FM.',
          'Rona' => 'Hardware, home improvement, and gardening products retailer based in Canada.',
          'Softonic' => 'Software download site.',
          'Kayak' => 'Online Flight and Hotel reservation/deals website.',
          'Scribd' => 'Web based document posting and sharing service.',
          'Business Insider' => 'Online news web portal.',
          'Badoo' => 'Social networking service.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'ProFlowers' => 'United States\' flower retailer.',
          'The Hollywood Reporter' => 'News related to the entertainment industry.',
          'eRecht24' => 'Russian Web portal for all legal related information.',
          'The Guardian' => 'Online news portal.',
          'European Union' => 'Official website for European Union.',
          'Blackberry sites' => 'Website for RIM\'s smartphone.',
          'NCAA' => 'National Collegiate Athletic Association - non-profit association for athletic programs.',
          'Best Buy' => 'Website and online retailer for national chain of electronics stores.',
          'Tudou' => 'Popular Chinese video sharing website.',
          'The Week Magazine' => 'Online new magazine.',
          'Zhihu.com' => 'Chinese Q&A website.',
          'SugarCRM' => 'Customer relationship management software company.',
          'Michigan Radio' => 'Public radio serving the American state of Michigan.',
          'Daum Cafe' => 'Daum forums and social networking.',
          'Alisoft' => 'IT company for wesites design and development.',
          'NewsNow' => 'News aggregator website that links to thousands of publications.',
          'Freee TV' => 'International television streaming.',
          'MyWebSearch' => 'Web portal.',
          'Disney' => 'Official Disney website.',
          'AOL Mail' => 'AOL\'s email client and webmail.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'WordReference.com' => 'Online dictionaries, translator and word games.',
          'Inbox.com' => 'Free web-based email service provider.',
          'Adobe Fonts' => 'Adobe Fonts is an online service which offers a subscription library of high-quality fonts.',
          'Ad4mat' => 'Ad site.',
          'Live365' => 'Internet radio.',
          'SoulSeek' => 'Peer-to-peer network.',
          'Ybrant Digital' => 'Advertisement site.',
          'MKRU' => 'News website for the Russian newspaper Moskovskij Komsomolets.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Sprint' => 'Voice, data and internet service provider.',
          'Naver Blog' => 'Naver blogging app.',
          'StayFriends' => 'German school focused social network.',
          'Bluefly' => 'Online fashion retailer.',
          'Nico Nico Douga Video' => 'Nico Nico Douga video streaming.',
          'Engadget' => 'E-commerce for gadgets and electronics.',
          'Sohu.com' => 'Chinese search engine with other services like games, advertising, etc.',
          'Detroit Free Press' => 'News local to Detroit metropolitan area.',
          'Wimbledon' => 'Tennis related website.',
          'Letterpress' => 'Word game for iOS.',
          'GameSpy' => 'Video game news, reviews, and previews website.',
          'BigBlueButton' => 'Web conferencing system.',
          'Ganji' => 'Chinese website for classified information.',
          'Yahoo! Finance' => 'Yahoo! Stock and finance website.',
          'Bing Maps' => 'Microsoft online mapping and directions service.',
          'CheapTickets' => 'Travel services company focused on the leisure market.',
          'RealClearPolitics' => 'Political news, opinions and polls website.',
          'Wikia' => 'Web portal to contribute and share the knowledge.',
          'KVOA.com' => 'NBC-affiliated news channel for Tucson, Arizona.',
          'Delta Search' => 'A search engine, with a toolbar that is commonly installed by mistake.',
          'Eset' => 'Eset Antivirus/Security software download and updates.',
          'TD Ameritrade' => 'Online stock brokerage service.',
          'GameTrailers' => 'Video game news, reviews, and previews website.',
          'Kohl\'s' => 'Department store/retailer.',
          'USAA' => 'Insurance company.',
          'OCLC' => 'Online Computer Library Center - Nonprofit collaboration for providing online public access catalog.',
          '126.com' => 'Free webmail system.',
          'Naver Mail' => 'Naver webmail.',
          'AMD' => 'A manufacturer or PC chipsets.',
          'Feedly' => 'News Aggregator.',
          'Cox' => 'Telecommunication and wireless service provider.',
          'Yesky' => 'Chinese IT portal.',
          'The Sharper Image' => 'General electronics and gifts retailer.',
          'Libsyn' => 'Podcast hosting services.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'PPTV' => 'Chinese file-streaming app.',
          'The Atlantic' => 'News portal.',
          'About.com' => 'A site that provides original information on various subjects.',
          'Autoblog' => 'Automobile news and information site.',
          'Walgreens' => 'Online Pharmacy in United States.',
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'CBS Sports' => 'Sports news website.',
          'Cheezburger' => 'Hang-out place for funny Photos and stories.',
          'Orbitz' => 'Internet based travel services company.',
          'MobiTV' => 'A content aggregation company focusing on video.',
          'Adap.tv' => 'Video advertising service.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'RuneScape' => 'Browser based fantasy role-playing game.',
          'PerfectIBE' => 'An air travel booking consolidation engine.',
          'Playstation.com' => 'Sony Playstation related e-commerce.',
          'Twitterrific' => 'Twitter client.',
          'Vine' => 'Mobile App for sharing photos and videos clips.',
          'MapleStory' => 'Online game portal.',
          'Grantland' => 'Web portal for sports news by ESPN.',
          'studiVZ' => 'German online classroom / social network.',
          'Chosun' => 'News aggregates from BBC in Korean.',
          'RetailMeNot' => 'Online coupon and deals.',
          'Zales' => 'Jewelry retailer.',
          'Crutchfield' => 'Electronics retailer.',
          'Snort.org' => 'An open source for Network intrusion prevention system.',
          'OwnerIQ' => 'Advertisement site.',
          'Tiger Direct' => 'Online computer and electronics retailer.',
          'Zombo.com' => 'Website where you can do anything.',
          'uTorrent' => 'BitTorrent client known for its lightweight and efficient design.',
          'AllRecipes' => 'Recipes and cooking guide.',
          'Neiman Marcus' => 'Luxury retail department store.',
          'SimplePie' => 'RSS Feed.',
          'Gyao' => 'Video streaming website by Yahoo! Japan.',
          'Bleacher Report' => 'Web Portal for Sports news update.',
          'Adify' => 'Advertisement site.',
          'Biography.com' => 'Stories, biographies about people.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'USPS' => 'US Postal Service website.',
          'VeriSign' => 'SSL Certificates provider.',
          'The Hype Machine' => 'MP3 blog aggregator.',
          'Diigo' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'WD softwares Download/Update' => 'Update/Download software provided by western digital.',
          'Aizhan' => 'Chinese web portal.',
          'Tuenti' => 'Invite only social networking website based in Spain.',
          'Fox News' => 'Web Portal for news update.',
          'schuelerVZ' => 'German online classroom / social network.',
          'WarriorForum' => 'Internet Marketing Forums.',
          'BitTorrent' => 'A peer-to-peer file sharing protocol used for transferring large amounts of data.',
          'Yellow Pages' => 'Online directory and Mapping services.',
          'Weebly' => 'Free, online website creation tool.',
          'Neteller' => 'Website for handling online payments and money transactions.',
          'Soso' => 'Chinese search engine.',
          'Library of Congress' => 'Online collection of American history memories and culture.',
          'NFL.com' => 'American football news.',
          'Soku' => 'Youku\'s search engine.',
          'Y8' => 'Internet gaming website.',
          'Eclipse Updates' => 'Software Updates for Eclipse.',
          'Dilbert.com' => 'Offcial website for Dilbert, American comic strips.',
          'HSBC' => 'Global banking and financial services company.',
          '33Across' => 'Social ad delivery service.',
          'Chatroulette' => 'Service that pairs random strangers for video chat.',
          'SmugMug' => 'Photo sharing website.',
          'Deezer' => 'Music streaming service based in Paris.',
          'McAfee' => 'McAfee Antivirus/Security software download and updates.',
          'CNET Download' => 'Download of content from CNET.',
          'TIME.com' => 'Webportal for TIME Magazine.',
          'Balatarin' => 'Social bookmarking and community website aimed at an Iranian audience.',
          'beRecruited' => 'College athletic social networking site.',
          'w3schools.com' => 'A web development learning website.',
          'CareerBuilder.com' => 'Online job search portal.',
          'Liberty Mutual' => 'Insurance company.',
          'AdSame' => 'Chinese digital marketting platform.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          'The Huffington Post' => 'Online news website.',
          'Associated Press' => 'Official web site for the Associated Press, non-profit news agency.',
          'Craigslist' => 'Popular online classifieds.',
          'WPS Office' => 'Mobile app for viewing and editing documents, spreadsheet and PPTs.',
          'Shoplet' => 'Office products retailer.',
          'AutoTrader.com' => 'Used car listings by owner or dealer.',
          'Mibbit' => 'Web based chat client that supports IRC and Twitter.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'ZergNet' => 'Content aggregator for Sci-Fi Article.',
          'AOL Games' => 'Online games on AOL.com.',
          'MapQuest' => 'Map and Driving service by AOL.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'Trac' => 'Web based bug tracking and project management tool.',
          'MyOnlineArcade' => 'Free web based games.',
          'Funny or Die' => 'Site that presents humorous videos and media.',
          'WhitePages Inc' => 'Business and People\'s Contact directory in United States.',
          'Food Network' => 'Official website for the TV network about food and cooking.',
          'GameStop' => 'Video game retailer.',
          '360 Safeguard' => 'Chinese anti-virus software.',
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'QQ' => 'Chinese instant messaging software.',
          'Dictionary.com' => 'Online free dictionary.',
          'Stanford University' => 'Official website for Stanford University, Educational Institute.',
          'Joomla' => 'Content Management System for building web sites.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  'ssl_host_group_334_part3',
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- ProxEasy
    { 0, 1001, 'proxeasy.com' },
    -- Qriocity
    { 0, 1002, 'qriocity.com' },
    -- RuneScape
    { 0, 1003, 'runescape.com' },
    -- Scribd
    { 0, 1005, 'scribd.com' },
    -- Songza
    { 0, 1006, 'songza.com' },
    -- Tudou
    { 0, 1014, 'tudou.com' },
    -- Tuenti
    { 0, 1016, 'tuenti.com' },
    -- VKontakte
    { 0, 1018, 'vk.com' },
    { 0, 1018, 'vkontakte.ru' },
    -- VTunnel
    { 0, 1019, 'vtunnel.com' },
    -- Webhard
    { 0, 1020, 'webhard.co.kr' },
    { 0, 1020, 'webhard.net' },
    -- Weibo
    { 0, 1022, 'weibo.com' },
    -- BigUpload
    { 0, 1027, 'bigupload.com' },
    -- Clarizen
    { 0, 1028, 'clarizen.com' },
    -- 56.com
    { 0, 1031, '56.com' },
    -- 51.com
    { 0, 1032, '51.com' },
    -- Youku
    { 0, 1033, 'youku.com' },
    -- Crackle
    { 0, 1034, 'crackle.com' },
    -- RuTube
    { 0, 1035, 'rutube.ru' },
    -- Afreeca
    { 0, 1037, 'afreeca.com' },
    { 0, 1037, 'afreecatv.com' },
    { 0, 1037, 'bizafreeca.com' },
    -- Babelgum
    { 0, 1038, 'babelgum.com' },
    -- Phanfare
    { 0, 1046, 'phanfare.com' },
    -- FilmOn
    { 0, 1048, 'filmon.com' },
    -- Mibbit
    { 0, 1049, 'mibbit.com' },
    -- BigBlueButton
    { 0, 1050, 'bigbluebutton.org' },
    -- MegaMeeting
    { 0, 1052, 'megameeting.co' },
    -- Badoo
    { 0, 1053, 'badoo.com' },
    -- CloudMe
    { 0, 1055, 'cloudme.com' },
    -- Skyrock
    { 0, 1057, 'skyrock.com' },
    -- Jubii
    { 0, 1060, 'jubii.dk' },
    -- TwitPic
    { 0, 1063, 'twitpic.com' },
    -- yfrog
    { 0, 1064, 'yfrog.com' },
    -- hi5.com
    { 0, 1066, 'hi5.com' },
    -- Livemocha
    { 0, 1067, 'livemocha.com' },
    -- Slacker
    { 0, 1068, 'slacker.com' },
    -- Douban
    { 0, 1069, 'douban.com' },
    -- Gaia Online
    { 0, 1071, 'gaiaonline.com' },
    -- AutoZone
    { 0, 1073, 'autozone.com' },
    -- Tesco.com
    { 0, 1077, 'tesco.com' },
    -- 4chan
    { 0, 1079, '4chan.org' },
    -- Rhapsody
    { 0, 1081, 'rhapsody.com' },
    -- Balatarin
    { 0, 1082, 'balatarin.com' },
    -- PC Connection
    { 0, 1109, 'pcconnection.com' },
    -- CafeMom
    { 0, 1129, 'cafemom.com' },
    -- Mininova
    { 0, 1133, 'mininova.org' },
    -- PayPal
    { 0, 1134, 'paypal.com' },
    -- Pinterest
    { 0, 1135, 'pinimg.com' },
    -- The Pirate Bay
    { 0, 1136, 'pirate-proxy.com' },
    { 0, 1136, 'pirateproxy.click' },
    { 0, 1136, 'proxybay.me' },
    { 0, 1136, 'proxybay.nl' },
    { 0, 1136, 'quluxingba.info' },
    { 0, 1136, 'thepiratebayorg.org' },
    { 0, 1136, 'tpb.herokuapp.com' },
    { 0, 1136, 'tpb.torrentproxy.nl' },
    { 0, 1136, 'tpbproxy.me' },
    { 0, 1136, 'tpbunion.com' },
    -- Technorati
    { 0, 1137, 'technorati.com' },
    -- TypePad
    { 0, 1139, 'typepad.com' },
    -- Bubble Witch Saga
    { 0, 1159, 'bubblewitch.king.com' },
    -- About.com
    { 0, 1167, 'about.com' },
    -- CNET
    { 0, 1170, 'cnet.com' },
    -- CNET Download
    { 0, 1171, 'download.cnet.com' },
    -- w3schools.com
    { 0, 1180, 'w3schools.com' },
    -- Weebly
    { 0, 1181, 'weebly.com' },
    { 0, 1181, 'weeblyimages1.com' },
    -- Apple sites
    { 0, 1185, 'imacstore.com' },
    -- CNN.com
    { 0, 1190, 'cnn-f.akamaihd.net' },
    { 0, 1190, 'cnnchile.com' },
    { 0, 1190, 'cnnios-f.akamaihd.net' },
    { 0, 1190, 'cnnmexico.com' },
    -- IMDB
    { 0, 1191, 'imdb.com' },
    -- BC News
    { 0, 1192, 'msnbc.com' },
    -- Dictionary.com
    { 0, 1195, 'dictionary.com' },
    { 0, 1195, 'dictionary.reference.com' },
    -- Bing Maps
    { 0, 1197, 'maps.bing.com' },
    -- 126.com
    { 0, 1206, '126.com' },
    -- 39.net
    { 0, 1207, '39.net' },
    -- Aizhan
    { 0, 1208, 'aizhan.com' },
    -- tease
    { 0, 1222, 'netease.com' },
    -- Soku
    { 0, 1226, 'soku.com' },
    -- Bejeweled Chrome Extension
    { 0, 1229, 'bejeweled.popcap.com' },
    { 0, 1229, 'gats.popcap.com' },
    -- iAstrology
    { 0, 1238, 'horoscope.s3.amazonaws.com' },
    -- Bejeweled Blitz
    { 0, 1252, 'labs.popcap.com' },
    { 0, 1256, '4399.cn' },
    { 0, 1256, '4399.com' },
    -- Admin5
    { 0, 1258, 'admin5.com' },
    -- Wretch
    { 0, 1262, 'wretch.cc' },
    { 0, 1263, 'y8.com' },
    -- The New York Times
    { 0, 1299, 'nyt.com' },
    -- Twitter Link Service
    { 0, 1300, 't.co' },
    -- Yahoo! Finance
    { 0, 1301, 'finance.yahoo.com' },
    -- Ad Mob
    { 0, 1307, 'admob.com' },
    -- ver
    { 0, 1309, 'naver.jp' },
    { 0, 1309, 'naver.net' },
    -- Doubleclick
    { 0, 1313, 'doubleclick.com' },
    -- Ad Nexus
    { 0, 1314, 'ib.adnxs.com' },
    -- Pandora TV
    { 0, 1327, 'pandora.tv' },
    -- eBay Bid
    { 0, 133, 'offer.befr.ebay.be' },
    { 0, 133, 'offer.benl.ebay.be' },
    { 0, 133, 'offer.ebay.at' },
    { 0, 133, 'offer.ebay.ca' },
    { 0, 133, 'offer.ebay.ch' },
    { 0, 133, 'offer.ebay.co.uk' },
    { 0, 133, 'offer.ebay.com.au' },
    { 0, 133, 'offer.ebay.com.hk' },
    { 0, 133, 'offer.ebay.com.my' },
    { 0, 133, 'offer.ebay.com.sg' },
    { 0, 133, 'offer.ebay.com' },
    { 0, 133, 'offer.ebay.de' },
    { 0, 133, 'offer.ebay.es' },
    { 0, 133, 'offer.ebay.fr' },
    { 0, 133, 'offer.ebay.ie' },
    { 0, 133, 'offer.ebay.in' },
    { 0, 133, 'offer.ebay.it' },
    { 0, 133, 'offer.ebay.nl' },
    { 0, 133, 'offer.ebay.ph' },
    { 0, 133, 'offer.ebay.pl' },
    -- USA Today
    { 0, 1335, 'usatoday.com' },
    -- Millennial Media
--    { 0, 1337, 'ads.mp.mydas.mobi' },
--    { 0, 1337, 'millennialmedia.com' },
    -- Weather Underground
    { 0, 1338, 'wunderground.com' },
    { 0, 1338, 'wxug.com' },
    -- Clubbox
    { 0, 1340, 'clubbox.co.kr' },
    -- Kiwoom
    { 0, 1341, 'kiwoom.com' },
    -- DCinside
    { 0, 1342, 'dcinside.com' },
    -- te
    { 0, 1343, 'nate.com' },
    -- Fileguri
    { 0, 1344, 'fileguri.com' },
    -- Baidu
    { 0, 1345, 'baidu.com' },
    { 0, 1345, 'bdstatic.com' },
    -- How
    { 0, 1363, 'ehow.com' },
    -- ESPN
    { 0, 1364, 'espncdn.com' },
    { 0, 1364, 'espn.com' },
    -- Fox News
    { 0, 1366, 'foxnews-f.akamaihd.net' },
    { 0, 1366, 'foxnews.com' },
    { 0, 1366, 'foxnews.demdex.net' },
    -- Weather.gov
    { 0, 1368, 'weather.gov' },
    -- The Huffington Post
    { 0, 1370, 'huffingtonpost.co.uk' },
    -- Conduit
    { 0, 1375, 'getu.com' },
    -- BBC
    { 0, 1376, 'bbc.co.uk' },
    { 0, 1376, 'bbc.com' },
    { 0, 1376, 'cbeebies.com' },
    { 0, 1376, 'feeds.bbci.co.uk' },
    -- Indeed
    { 0, 1378, 'indeed.com' },
    -- Publishers Clearing House
    { 0, 1379, 'pch.com' },
    -- Aweber
    { 0, 1381, 'aweber.com' },
    -- Fox Sports
    { 0, 1382, 'foxsports.com' },
    -- Searchnu
    { 0, 1383, 'searchnu.com' },
    -- Wall Street Journal
    { 0, 1390, 'fins.com' },
    { 0, 1390, 'smartmoney.com' },
    -- Daily Mail
    { 0, 1391, 'dailymail.co.uk' },
    -- Taobao
    { 0, 1399, 'taobao.com' },
    -- Engadget
    { 0, 1401, 'engadget.com' },
    -- Eclipse Updates
    { 0, 1412, 'download.eclipse.org' },
    -- Eclipse Marketplace
    { 0, 1414, 'marketplace.eclipse.org' },
    -- AOL
    { 0, 1419, 'aol.co.uk' },
    { 0, 1419, 'aol.ie' },
    { 0, 1419, 'aol.in' },
    { 0, 1419, 'aol.sg' },
    -- AdNetwork.net
    { 0, 1425, 'adnetwork.net' },
    -- Wolfram Alpha
    { 0, 1429, 'wolframalpha.com' },
    -- Eset
    { 0, 143, 'eset.eu' },
    { 0, 143, 'eset.sk' },
    -- VeriSign
    { 0, 1458, 'verisign.com' },
    -- CBS Sports
    { 0, 1459, 'cbssports.com' },
    -- InsightExpress
    { 0, 1461, 'ad.insightexpressai.com' },
    { 0, 1461, 'insightexpress.com' },
    -- Monster.com
    { 0, 1481, 'monster.com' },
    -- MapQuest
    { 0, 1482, 'mapquest.com' },
    -- Swagbucks
    { 0, 1483, 'swagbucks.com' },
    -- Verizon
    { 0, 1484, 'verizon.com' },
    { 0, 1484, 'verizon.net' },
    -- Wikia
    { 0, 1485, 'a.wikia-beacon.com' },
    { 0, 1485, 'wikia.com' },
    { 0, 1485, 'wikia.nocookie.net' },
    -- TMZ
    { 0, 1486, 'tmz.com' },
    -- HootSuite
    { 0, 1489, 'hootsuite.com' },
    -- Coupons.com
    { 0, 1490, 'coupons.com' },
    -- CareerBuilder.com
    { 0, 1491, 'careerbuilder.com' },
    { 0, 1491, 'icbdr.com' },
    -- Fiverr
    { 0, 1493, 'fiverr.com' },
    { 0, 1493, 'fiverrcdn.com' },
    -- AllRecipes
    { 0, 1496, 'allrecipes.com' },
    -- Yellow Pages
    { 0, 1497, 'yp.com' },
    -- Bleacher Report
    { 0, 1498, 'bleacherreport.com' },
    { 0, 1498, 'bleacherreport.net' },
    -- Stack Overflow
    { 0, 1499, 'stackoverflow.com' },
    -- Ancestry.com
    { 0, 1501, 'ancestry.com' },
    -- Business Insider
    { 0, 1505, 'businessinsider.com' },
    -- People.com
    { 0, 1506, 'peoplestylewatch.com' },
    --{ 0, 1506, 'timeinc.net' },
    -- Reuters
    { 0, 1507, 'reuters.com' },
    { 0, 1507, 'reutersmedia.com' },
    -- California.gov
    { 0, 1509, 'ca.gov' },
    -- Southwest Airlines
    { 0, 1510, 'southwest.com' },
    { 0, 1510, 'southwestairlines.tt.omtrdc.net' },
    -- IH
    { 0, 1511, 'nih.gov' },
    -- WhitePages Inc
    { 0, 1512, 'whitepages.com' },
    -- MGID
    { 0, 1513, 'mgid.com' },
    -- EarthLink
    { 0, 1514, 'earthlink.net' },
    { 0, 1514, 'earthlinkbusiness.com' },
    -- Disney
    { 0, 1515, 'disney.co.uk' },
    { 0, 1515, 'disney.com' },
    { 0, 1515, 'disneyinternational.com' },
    -- POLITICO.com
    { 0, 1516, 'politico.com' },
    -- Examiner.com
    { 0, 1518, 'examiner.com' },
    -- RetailMeNot
    { 0, 1519, 'retailmenot.com' },
    { 0, 1519, 'rmncdn.com' },
    -- AddThis
    { 0, 1520, 'addthis.com' },
    -- OkCupid
    { 0, 1522, 'okccdn.com' },
    { 0, 1522, 'okcimg.com' },
    { 0, 1522, 'okcupid.com' },
    -- Patch.com
    { 0, 1523, 'patch.com' },
    -- Realtor.com
    { 0, 1525, 'realtor.com' },
    -- Intuit
    { 0, 1526, 'intuit.com' },
    { 0, 1526, 'intuitstatic.com' },
    -- The Blaze
    { 0, 1527, 'gbtv.com' },
    { 0, 1527, 'theblaze.com' },
    -- HostGator
    { 0, 1528, 'hostgator.com' },
    -- Food Network
    { 0, 1529, 'foodnetwork.com' },
    -- ClickBank
    { 0, 1530, 'clickbank.com' },
    -- Cox
    { 0, 1531, 'cox.com' },
    { 0, 1531, 'cox.net' },
    -- Mashable
    { 0, 1532, 'mshcdn.com' },
    -- AccuWeather
    { 0, 1533, 'accuweather.com' },
    -- Sprint
    { 0, 1534, 'sprint.com' },
    -- Goodreads
    { 0, 1535, 'goodreads.com' },
    -- LiveStrong.com
    { 0, 1536, 'livestrong.com' },
    -- RealClearPolitics
    { 0, 1537, 'realclearpolitics.com' },
    -- Manta
    { 0, 1538, 'manta.com' },
    -- CNBC
    { 0, 1540, 'cnbc.com' },
    -- Inbox.com
    { 0, 1542, 'inbox.com' },
    -- teller
    { 0, 1544, 'neteller.com' },
    -- T Mobile
    { 0, 1545, 'tmobile.com' },
    { 0, 1545, 'tmobile.tt.omtrdc.net' },
    -- Walgreens
    { 0, 1546, 'walgreens.com' },
    -- WorldstarHipHop
    { 0, 1547, 'worldstarhiphop.com' },
    -- PR
    { 0, 1548, 'npr.org' },
    -- Kayak
    { 0, 1549, 'kayak.com' },
    -- ToysRUs
    { 0, 1550, 'trus.imageg.net' },
    -- Sohu.com
    { 0, 1552, 'sohu.com' },
    -- 1&1 Internet
    { 0, 1553, '1and1.com' },
    -- Ameba
    { 0, 1554, 'ameba.jp' },
    -- Avaya
    { 0, 1555, 'avaya.com' },
    -- Snort.org
    { 0, 1557, 'snort.org' },
    -- Disqus
    { 0, 1558, 'disqus.com' },
    -- Infusionsoft
    { 0, 1559, 'infusionsoft.com' },
    -- Alisoft
    { 0, 1561, 'alisoft.net' },
    -- Salesforce.com Live Agent
    { 0, 1562, 'liveagentforsalesforce.com' },
    -- Fab.com
    { 0, 1567, 'fab.com' },
    -- GoToMyPC
    { 0, 1598, 'gotomypc.com' },
    -- USPS
    { 0, 1601, 'uspspostalone.com' },
    -- FogBugz
    { 0, 161, 'fogbugz.com' },
    -- Yandex
    { 0, 1616, 'yandex.net' },
    -- The Guardian
    { 0, 1618, 'guardiannews.com' },
    -- WarriorForum
    { 0, 1622, 'warriorforum.com' },
    -- Indiatimes
    { 0, 1623, 'indiatimes.com' },
    -- UOL
    { 0, 1626, 'imguol.com' },
    { 0, 1626, 'jsuol.com' },
    -- LeTV
    { 0, 1650, 'letv.com' },
    -- Tianya
    { 0, 1651, 'tianya.cn' },
    { 0, 1651, 'tianyaui.com' },
    -- YY
    { 0, 1663, 'hiido.cn' },
    { 0, 1663, 'hiido.com' },
    { 0, 1663, 'yy.com' },
    -- Fancy
    { 0, 1668, 'thefancy.s3.amazonaws.com' },
    -- Flexera Software
    { 0, 1676, 'flexerasoftware.com' },
    { 0, 1676, 'installshield.com' },
    -- OsiriX
    { 0, 1677, 'osirix-viewer.com' },
    -- SOUNDROP
    { 0, 1695, 'soundrop.fm' },
    -- Vine
    { 0, 1700, 'vines.s3.amazonaws.com' },
    -- Linux Mint
    { 0, 1707, 'linuxmint.com' },
    -- Playstation.com
    { 0, 1754, 'playstation.com' },
    -- VLC Media Player
    { 0, 1756, 'videolan.org' },
    -- Bizrate
    { 0, 1782, 'bizrate.com' },
    -- Cute Overload
    { 0, 1784, 'cuteoverload.com' },
    { 0, 1784, 'cuteoverload.files.wordpress.com' },
    -- Cheezburger
    { 0, 1785, 'cheezburger.com' },
    -- theCHIVE
    { 0, 1788, 'cdn.thechivemobile.com.edgesuite.net' },
    { 0, 1788, 'chivethethrottle.files.wordpress.com' },
    { 0, 1788, 'shechive.files.wordpress.com' },
    { 0, 1788, 'theberry.com' },
    { 0, 1788, 'thebrigade.com' },
    { 0, 1788, 'thechive.com' },
    -- ZergNet
    { 0, 1790, 'zergnet.com' },
    -- WhereCoolThingsHappen
    { 0, 1791, 'wherecoolthingshappen.com' },
    -- Feedly
    { 0, 1799, 'feedly.com' },
    -- MTv
    { 0, 1805, 'mtv.com' },
    { 0, 1805, 'mtvn.demdex.net' },
    { 0, 1805, 'mtvnimages.com' },
    -- PubNub
    { 0, 1822, 'pubnub.com' },
    -- BC
    { 0, 1988, 'nbcdotcom-f.akamaihd.net' },
    { 0, 1988, 'nbcudigitaladops.com' },
    { 0, 1988, 'nbcuni.com' },
    { 0, 1988, 'nbcustr.netmng.com' },
    { 0, 1988, 'nbcvod-i.akamaihd.net' },
    -- Space.com
    { 0, 1990, 'space.com' },
    -- Zmags
    --{ 0, 1994, 'zmags.app4.hubspot.com' },
    -- ESTsoft
    { 0, 1996, 'estsoft.com' },
    -- Cabal Online
    { 0, 1997, 'cabal.estgames.com' },
    { 0, 1997, 'cabalsea.com' },
    -- Biography.com
    { 0, 2002, 'biography.com' },
    { 0, 2002, 'biography.disqus.com' },
    -- Comedy Central
    { 0, 2004, 'cc.com' },
    { 0, 2004, 'colbertnation.com' },
    { 0, 2004, 'colbertnation.mtvnimages.com' },
    { 0, 2004, 'comedycentral.com' },
    { 0, 2004, 'jokes.com' },
    { 0, 2004, 'jokes.mtvnimages.com' },
    { 0, 2004, 'thedailyshow.com' },
    { 0, 2004, 'thedailyshow.mtvnimages.com' },
    { 0, 2004, 'viacomedycentral.112.2o7.net' },
    -- Wired.com
    { 0, 2005, 'wiredinsider.tumblr.com' },
    { 0, 2005, 'wiredopinion.disqus.com' },
    -- E! Online
    { 0, 2006, 'eonline.com' },
    -- HL.com
    { 0, 2007, 'nhl.cdnllnwnl.neulion.net' },
    -- TopTenREVIEWS
    { 0, 2016, 'toptenreviews.com' },
    -- Adweek
    { 0, 2017, 'adweek.com' },
    { 0, 2017, 'adweekmedia.disqus.com' },
    -- The Week Magazine
    { 0, 2018, 'theweekus.disqus.com' },
    -- wser
    { 0, 2020, 'newser.com' },
    -- FOX
    { 0, 2050, 'fbchdvod-f.akamaihd.net' },
    { 0, 2050, 'fox.com' },
    { 0, 2050, 'foxnet.demdex.net' },
    { 0, 2050, 'foxnetworks.tt.omtrdc.net' },
    -- Washington Times
    { 0, 2051, 'washingtontimes.com' },
    { 0, 2051, 'washtimes.com' },
    { 0, 2051, 'washtimes.disqus.com' },
    -- xtBus
    { 0, 2052, 'nextbus.com' },
    -- OpenBSD
    { 0, 2053, 'openbsd.com' },
    { 0, 2053, 'openbsd.org' },
    -- Associated Press
    { 0, 2054, 'ap.org' },
    -- WTOP
    { 0, 2055, 'wtop.com' },
    -- OpenSUSE
    { 0, 2056, 'opensuse.com' },
    -- NCAA
    { 0, 2058, 'ncaa.com' },
    { 0, 2058, 'ncaa.org' },
    -- DSW
    { 0, 2059, 'dsw.112.2o7.net' },
    -- Clear Channel
    { 0, 2064, 'clearchannelinternational.com' },
    -- GOLF.com
    { 0, 2065, 'golf.com' },
    -- OCLC
    { 0, 2070, 'oclc.org' },
    -- Chosun
    { 0, 2071, 'chosun.com' },
    -- Game Front
    { 0, 2082, 'gamefront.com' },
    -- BitCoin
    { 0, 2083, 'bitcoin.org' },
    -- Letterpress
    { 0, 2091, 'atebits.com' },
    -- Entertainment Weekly
    --{ 0, 2095, 'timeinc.net' },
    -- Speedtest
    { 0, 2103, 'speedtest.centurylink.net' },
    { 0, 2103, 'speedtest.net' },
    -- Boxnet Upload SSL
    { 0, 2104, 'upload.box.com' },
    -- Flickr Upload
    { 0, 2105, 'up.flickr.com' },
    -- Microsoft Azure
    { 0, 2111, 'thewindowsazureproductsite.disqus.com' },
    -- Adblade
    { 0, 2116, 'adblade.com' },
    -- Blackberry sites
    { 0, 2119, 'blackberry.com' },
    -- Djpod
    { 0, 2120, 'djpod.com' },
    -- MyOnlineArcade
    { 0, 2123, 'myonlinearcade.com' },
    -- SmugMug
    { 0, 2124, 'smugmug.com' },
    -- USAA
    { 0, 2126, 'usaa.com' },
    -- wimp.com
    { 0, 2127, 'wimp.com' },
    -- Show My Weather
    { 0, 2130, 'showmyweather.com' },
    -- MobiTV
    { 0, 2131, 'mobitv.com' },
    -- TV Guide
    { 0, 2132, 'tvguide.com' },
    -- Media Hub
    { 0, 2136, 'samsungmediahub.net' },
    -- CheapOAir
    { 0, 2137, 'cheapoair.com' },
    -- Intel
    { 0, 2143, 'intel.com' },
    -- AMD
    { 0, 2144, 'amd.com' },
    -- Acer
    { 0, 2146, 'acer.com' },
    -- Gateway
    { 0, 2147, 'gateway.com' },
    -- Motorola
    { 0, 2149, 'motorola.com' },
    -- Progressive
    { 0, 2152, 'progressive.com' },
    -- State Farm
    { 0, 2153, 'statefarm.com' },
    -- Liberty Mutual
    { 0, 2156, 'libertymutual.com' },
    -- PerfectIBE
    { 0, 2162, 'perfectibe.com' },
    -- Funny or Die
    { 0, 2163, 'funnyordie.com' },
    { 0, 2163, 'ordienetworks.com' },
    -- Zombo.com
    { 0, 2165, 'zombo.com' },
    -- Viki
    { 0, 2171, 'viki.com' },
    -- Al Jazeera
    { 0, 2180, 'aljazeera.com' },
    { 0, 2180, 'aljazeera.net' },
    -- Wimbledon
    { 0, 2181, 'wimbledon.com' },
    -- Times Union
    { 0, 2183, 'timesunion.com' },
    -- beRecruited
    { 0, 2184, 'berecruited.com' },
    -- Detroit Free Press
    { 0, 2186, 'freep.com' },
    -- Michigan Radio
    { 0, 2188, 'michiganradio.org' },
    -- De Telegraaf
    { 0, 2189, 'telegraaf.nl' },
    -- The Daily Beast
    { 0, 2191, 'thedailybeast.com' },
    -- The Free Dictionary
    { 0, 2192, 'thefreedictionary.com' },
    -- The Onion
    { 0, 2193, 'theonion.com' },
    -- Collider
    { 0, 2207, 'collider.com' },
    -- WordReference.com
    { 0, 2208, 'wordreference.com' },
    -- SpeedRunsLive
    { 0, 2238, 'speedrunslive.com' },
    -- WDT
    { 0, 2240, 'wdtinc.com' },
    -- Twitterrific
    { 0, 2241, 'twitterrific.com' },
    -- The Seattle Times
    { 0, 2242, 'seattletimes.com' },
    -- Okta
    { 0, 2246, 'okta.com' },
    -- ike
    { 0, 2247, 'nike.com' },
    -- Libsyn
    { 0, 2248, 'libsyn.com' },
    -- Investopedia
    { 0, 2250, 'investopedia.com' },
    -- The Hollywood Reporter
    { 0, 2251, 'hollywoodreporter.com' },
    -- CNET TV
    { 0, 2256, 'cnettv.cnet.com' },
    -- Adap.tv
    { 0, 2261, 'adap.tv' },
    -- Drugs.com
    { 0, 2269, 'drugs.com' },
    -- Wood TV8
    { 0, 2285, 'woodtv.com' },
    -- uTorrent
    { 0, 2299, 'utorrent.com' },
    -- Tinder
    { 0, 2302, 'gotinder.com' },
    -- Apache Nutch
    { 0, 2330, 'nutch.apache.org' },
    { 0, 2346, '2345.cn' },
    { 0, 2346, '2345.com' },
    -- Forbes
    { 0, 2347, 'forbes.com' },
    -- Freee TV
    { 0, 2348, 'freeetv.com' },
    -- IKEA.com
    { 0, 2349, 'ikea.is' },
    -- CBS Interactive
    { 0, 2354, 'cbsinteractive.com' },
    -- MyWebSearch
    { 0, 2365, 'mywebsearch.com' },
    -- China.com
    { 0, 2371, 'china.com' },
    -- In.com
    { 0, 2372, 'in.com' },
    -- FL.com
    { 0, 2376, 'nfl.com' },
    -- wetpaint entertainment
    { 0, 2378, 'wetpaint.com' },
    { 0, 2378, 'wetpaint.me' },
    -- PPTV
    { 0, 2380, 'pptv.com' },
    -- Alibaba
    { 0, 2386, 'alibabagroup.com' },
    -- Etao
    { 0, 2388, 'etao.com' },
    -- Amazon
    { 0, 24, 'amazon-presse.de' },
    -- 33Across
    { 0, 2419, '33across.com' },
    { 0, 2419, 'tynt.com' },
    -- The Atlantic
    { 0, 2424, 'atlanticmedia.122.2o7.net' },
    { 0, 2424, 'theatlantic.com' },
    { 0, 2424, 'theatlantic.disqus.com' },
    -- The Escapist Magazine
    { 0, 2430, 'escapistmagazine.com' },
    -- Grantland
    { 0, 2432, 'grantland.com' },
    -- The Independent
    { 0, 2433, 'independent.co.uk' },
    { 0, 2433, 'independentnews.disqus.com' },
    -- Komli Media
    { 0, 2463, 'komli.com' },
    -- Android.com
    { 0, 2470, 'android.com' },
    -- Freelancer
    { 0, 2483, 'freelancer.co.uk' },
    -- Goal
    { 0, 2484, 'goal.com' },
    -- 247 Inc.
    { 0, 2492, '247-inc.com' },
    -- SLI Systems
    { 0, 2494, 'sli-systems.co.jp' },
    { 0, 2494, 'sli-systems.com.au' },
    { 0, 2494, 'sli-systems.com.br' },
    -- OwnerIQ
    { 0, 2495, 'owneriq.com' },
    -- Monetate
    { 0, 2496, 'monetate.com' },
    -- Adtech
    { 0, 2503, 'adtech-kansai.com' },
    { 0, 2503, 'adtech-tokyo.com' },
    -- Amobee
    { 0, 2504, 'amobee.com' },
    -- Mobile Theory
    { 0, 2506, 'mobiletheory.com' },
    -- Casale
    { 0, 2512, 'casalemedia.com' },
    -- Exponential Interactive
    { 0, 2518, 'exponential.com' },
    -- eyeReturn
    { 0, 2526, 'eyeReturn.com' },
    { 0, 2526, 'eyereturnmarketing.com' },
    -- InSkin Media
    { 0, 2527, 'inskinad.com' },
    { 0, 2527, 'inskinmedia.com' },
    -- ustar Information Services
    { 0, 2537, 'neustarlife.biz' },
    { 0, 2537, 'neustarsummit.biz' },
    { 0, 2537, 'tcpacompliance.com' },
    -- Ybrant Digital
    { 0, 2546, 'lygo.com' },
    { 0, 2546, 'www.volomp.com' },
    -- { 0, 2546, 'ybrantmobile.com' },
    -- Federated Media
    { 0, 2559, 'federatedmedia.net' },
    -- Adify
    { 0, 2570, 'adify.com' },
    -- Aptean
    { 0, 2581, 'aptean.com' },
    -- VoiceFive
    { 0, 2584, 'VoiceFive.com' },
    -- Telecom Express
    { 0, 2588, 'www.telecomexpress.co.uk' },
    -- CNZZ
    { 0, 2597, 'cnzz.com' },
    -- Softonic
    { 0, 2599, 'softonic.cn' },
    { 0, 2599, 'softonic.com.br' },
    { 0, 2599, 'softonic.de' },
    { 0, 2599, 'softonic.fr' },
    { 0, 2599, 'softonic.it' },
    { 0, 2599, 'softonic.jp' },
    { 0, 2599, 'softonic.pl' },
    -- Softpedia
    { 0, 2606, 'softpedia.com' },
    -- China News
    { 0, 2610, 'chinanews.com.cn' },
    { 0, 2610, 'chinanews.com' },
    -- Nico Nico Douga Video
    { 0, 2611, 'live.nicovideo.jp' },
    -- Aliwangwang
    --{ 0, 2617, 'taobao.com' },
    { 0, 2617, 'wangwang.taobao.com' },
    { 0, 2617, 'wangxin.taobao.com' },
    -- Xbox Live sites
    --{ 0, 2626, 'xbox.com' },
    -- GOMTV Remote Control
    { 0, 2638, 'remoteapi.gomlab.com' },
    -- Live365
    { 0, 264, 'live365.com' },
    -- GoToTraining
    { 0, 2642, 'gototraining.com' },
    -- PNAS
    { 0, 2651, 'pnascentral.org' },
    -- Stitcher
    { 0, 2653, 'stitcher.assets.s3.amazonaws.com' },
    -- The Baltimore Sun
    { 0, 2656, 'baltimoresun.com' },
    -- Dilbert.com
    { 0, 2657, 'dilbert.com' },
    -- INRIX
    { 0, 2662, 'inrix.com' },
    -- Lijit
    { 0, 2663, 'lijit.com' },
    -- Moat
    { 0, 2664, 'moat.com' },
    { 0, 2664, 'moatads.com' },
    { 0, 2664, 'moatsearch-data.s3.amazonaws.com' },
    -- ibVPN Login
    --{ 0, 2680, 'ibvpn.com' },
    -- Fuyin.TV
    { 0, 2696, 'fuyin.tv' },
    -- SHOWTIME ANYTIME
    { 0, 2697, 'sho.com' },
    -- Sky.com
    { 0, 2699, 'skynews.com' },
    { 0, 2699, 'skysports.com' },
    -- EA Games
    { 0, 2701, 'easports.com' },
    { 0, 2701, 'maxis.com' },
    { 0, 2701, 'simcity.com' },
    { 0, 2701, 'thesims.com' },
    -- Gizmodo
    { 0, 2705, 'gizmodo.com' },
    -- SimplePie
    { 0, 2706, 'simplepie.org' },
    -- Zippyshare
    { 0, 2738, 'zippyshare.com' },
    -- GTA Online
    --{ 0, 2740, 'rockstargames.com' },
    -- Rockstar Games
    { 0, 2747, 'rockstargames.com' },
    { 0, 2747, 'rockstarleeds.co.uk' },
    { 0, 2747, 'rockstarlincoln.com' },
    { 0, 2747, 'rockstarnewengland.com' },
    { 0, 2747, 'rockstarnorth.com' },
    { 0, 2747, 'rockstarsandiego.com' },
    { 0, 2747, 'rockstartoronto.com' },
    -- CTV News
    { 0, 2751, 'ctvnews.cookieless.ca' },
    -- KVOA.com
    { 0, 2753, 'kvoa.com' },
    -- MovieTickets.com
    { 0, 2755, 'movieticketscom.122.2o7.net' },
    -- Tvigle
    { 0, 2761, 'tvigle.com' },
    { 0, 2761, 'tvigle.ru' },
    -- SFGate
    { 0, 2765, 'sfgate.com' },
    -- Library of Congress
    { 0, 2766, 'loc.gov' },
    -- OverBlog
    { 0, 2767, 'over-blog-kiwi.com' },
    { 0, 2767, 'over-blog.net' },
    { 0, 2767, 'overblog.com' },
    -- TIME.com
    { 0, 2770, 'timeinc.net' },
    -- Phoca
    { 0, 2771, 'phoca.cz' },
    -- Joomla
    { 0, 2779, 'joomla.org' },
    { 0, 2779, 'joomlacode.org' },
    -- Stanford University
    { 0, 2783, 'gostanford.com' },
    -- Recht24
    { 0, 2785, 'e-recht24.de' },
    -- European Union
    { 0, 2786, 'europa.eu' },
    -- McAfee
    { 0, 280, 'mcafee12.tt.omtrdc.net' },
    -- Office 365
    { 0, 2812, 'Home.Office.com' },
    { 0, 2812, 'Portal.Office.com' },
    -- Picsearch
    { 0, 2816, 'picsearch.com' },
    -- Fetion
    { 0, 2817, 'feixin.10086.cn' },
    -- Hangame
    { 0, 2832, 'hangame.co.jp' },
    -- SugarCRM
    { 0, 2833, 'sugarcrm.com' },
    -- Pastebin.com
    { 0, 2839, 'pastebin.com' },
    -- Zhihu.com
    { 0, 2840, 'zhihu.com' },
    -- Adobe Analytics
    { 0, 2846, 'adobe.tt.omtrdc.net' },
    -- AdSame
    { 0, 2849, 'adsame.com' },
    -- Ganji
    { 0, 2854, 'ganji.com' },
    -- BBC iPlayer
    --{ 0, 2857, 'bbc.co.uk' },
    -- Zol.com.cn
    { 0, 2866, 'zol-img.com.cn' },
    { 0, 2866, 'zol.com.cn' },
    -- Baidu Movies
    { 0, 2869, 'movie.baidu.com' },
    { 0, 2869, 'v.baidu.com' },
    { 0, 2869, 'video.baidu.com' },
    -- Xunlei Kankan
    { 0, 2878, 'kankan.com' },
    { 0, 2878, 'sandai.net' },
    { 0, 2878, 'xlpan.com' },
    { 0, 2878, 'xunlei.com' },
    -- Myspace Photos
    --{ 0, 2882, 'myspace.com' },
    -- Myspace Videos
    --{ 0, 2883, 'myspace.com' },
    -- Gyao
    { 0, 2885, 'gyao.c.yimg.jp' },
    { 0, 2885, 'gyao.yahoo.co.jp' },
    -- Glype
    { 0, 2891, 'glype.com' },
    -- Sanook.com
    { 0, 2893, 'sanook.com' },
    -- YiXin
    --{ 0, 2914, 'netease.com' },
    -- Tomatopang
    { 0, 2943, 'tomatopang.net' },
    -- Sina Video
    { 0, 2948, 'video.sina.com' },
    -- Crackle Video
    --{ 0, 2955, 'crackle.com' },
    -- Napster
    { 0, 319, 'napster.co.uk' },
    { 0, 319, 'napster.com' },
    -- VPNReactor
    { 0, 3652, 'vpnreactorsupport.com' },
    { 0, 3652, 'vprdownload.com' },
    -- Delta Search
    { 0, 3657, 'delta-search.com' },
    { 0, 3657, 'royal-search.com' },
    -- news.com.au
    { 0, 3671, 'news.com.au' },
    -- Soso
    { 0, 3673, 'soso.com' },
    -- Ad4mat
    { 0, 3702, 'ad4mat.com' },
    { 0, 3702, 'ad4mat.de' },
    { 0, 3702, 'ad4mat.net' },
    -- Cedexis
    { 0, 3705, 'cedexis.com' },
    -- L'equipe.fr
    { 0, 3711, 'lequipe.fr' },
    { 0, 3711, 'lequipe21.fr' },
    { 0, 3711, 'logc215.xiti.com' },
    -- Proxistore
    { 0, 3717, 'proxistore.com' },
    -- Viewsurf
    { 0, 3722, 'viewsurf.com' },
    -- XiTi
    { 0, 3724, 'atinternet.com' },
    -- OneDrive
    { 0, 3735, 'ssw.live.com' },
    { 0, 3735, 'g.live.com' },
    -- LinkedIn Contacts
    { 0, 3736, 'contacts.linkedin.com' },
    -- Rackspace
    { 0, 3737, 'rackspace.com' },
    -- ServiceNow
    { 0, 3738, 'servicenow.com' },
    -- PPStream
    { 0, 374, 'pps.tv' },
    { 0, 374, 'ppstream.com' },
    -- Blizzard
    { 0, 3745, 'blizzard.com' },
    { 0, 3745, 'blzstatic.cn' },
    { 0, 3745, 'blznews.akamaized.net' },
    { 0, 3745, 'blzprofile.akamaized.net' },
    { 0, 3745, 'blzmedia-a.akamaihd.net' },
    -- USAIP
    { 0, 3755, 'usaip.eu' },
    -- Yahoo! Douga
    { 0, 3756, 'streaming.yahoo.co.jp' },
    -- Clip2Net
    { 0, 3782, 'clip2net.com' },
    -- Yesky
    { 0, 3790, 'yesky.com' },
    -- Lineage
    { 0, 3801, 'lineage.com' },
    { 0, 3801, 'lineage.plaync.com' },
    { 0, 3801, 'lineage2.com' },
    -- MapleStory
    { 0, 3802, 'maplestory.nexon.net' },
    -- Level 3
    { 0, 3805, 'level3.com' },
    -- MissLee
    { 0, 3815, 'misslee.net' },
    -- QDown
    { 0, 3817, 'qdown.com' },
    -- BaiduHi
    { 0, 3838, 'im.baidu.com' },
    -- Ad Master
    { 0, 3846, 'admaster.com.cn' },
    -- Ad Tech
    { 0, 3847, 'adtech.com' },
    { 0, 3847, 'adtech.de' },
    { 0, 3847, 'adtechus.com' },
    { 0, 3847, 'oneadserver.aol.com' },
    -- QQ
    { 0, 386, 'qpic.cn.com' },
    -- 360 Safeguard
    { 0, 3866, '360.cn' },
    -- People's Daily
    { 0, 3868, 'people.com.cn' },
    -- China Daily
    { 0, 3871, 'chinadaily.com.cn' },
    -- Guangming Online
    { 0, 3872, 'gmw.cn' },
    -- Autodesk
    { 0, 3888, 'autodesk.com' },
    -- Wow
    { 0, 3910, 'wow.com' },
    -- Tencent Video
    { 0, 3942, 'vm.gtimg.cn' },
    -- Hulu Video
    --{ 0, 3946, 'hulu.com' },
    -- Flipkart
    { 0, 3970, 'flipkart.com' },
    -- SUPERAntiSpyware
    { 0, 3991, 'superantispyware.com' },
    -- WPS Office
    { 0, 4010, 'kingsoftstore.com' },
    { 0, 4010, 'wps.cn' },
    -- Kontiki
    { 0, 4013, 'kontiki.com' },
    -- Western Digital
    { 0, 4039, 'wdc.com' },
    -- WD softwares Download/Update
    { 0, 4040, 'download.wdc.com' },
    -- Baidu Yun
    { 0, 4043, 'yun.baidu.com' },
    -- Adobe Fonts
    { 0, 4602, 'p.typekit.net' },
    -- Naver Blog
    { 0, 4050, 'blog.naver.com' },
    -- { 0, 4050, 'blog.poll.naver.com' },
    { 0, 4050, 'blogfiles13.naver.net' },
    { 0, 4050, 'blogfiles4.naver.net' },
    { 0, 4050, 'blogfiles5.naver.net' },
    { 0, 4050, 'blogfiles9.naver.net' },
    { 0, 4050, 'blogimgs.naver.com' },
    { 0, 4050, 'blogimgs.naver.net' },
    { 0, 4050, 'blogpfthumb.phinf.naver.net' },
    { 0, 4050, 'blogthumb2.naver.net' },
    { 0, 4050, 'mblogthumb4.phinf.naver.net' },
    { 0, 4050, 'static.naver.net' },
    -- Naver Cafe
    { 0, 4051, 'cafe.naver.com' },
    { 0, 4051, 'cafefiles.naver.net' },
    { 0, 4051, 'cafeimgs.naver.net' },
    { 0, 4051, 'cafeptthumb1.phinf.naver.net' },
    { 0, 4051, 'cafeptthumb2.phinf.naver.net' },
    { 0, 4051, 'cafeptthumb3.phinf.naver.net' },
    -- { 0, 4051, 'cafeptthumb4.phinf.naver.net' },
    { 0, 4051, 'lcs.naver.com' },
    -- Daum Cafe
    { 0, 4053, 'cafeimg.daum-img.net' },
    -- Naver Mail
    { 0, 4054, 'mail.naver.com' },
    -- WebM Files
    { 0, 4109, 'webmfiles.org' },
    -- AOL Games
    { 0, 4117, 'games.aol.co.uk' },
    { 0, 4117, 'games.aol.com' },
    { 0, 4117, 'games.aol.de' },
    { 0, 4117, 'spiele.aol.de' },
    -- Nintendo
    { 0, 4130, 'nintendo.fr' },
    -- Showbox
    { 0, 4149, 'apk.org' },
    { 0, 4149, 'apkmirror.com' },
    { 0, 4149, 'showbox.org' },
    { 0, 4149, 'showboxapp.com' },
    { 0, 4149, 'showboxappandroid.com' },
    { 0, 4149, 'showboxappdownload.co' },
    -- { 0, 4149, 'showboxappdownloads.com' },
    -- SoulSeek
    { 0, 442, 'slsknet.org' },
    { 0, 442, 'soulseekqt.net' },
    -- MKRU
    { 0, 4522, 'mk.ru' },
    -- MKRU Streaming
    { 0, 4523, 'tv.mk.ru' },
    -- Vonage
    { 0, 495, 'vonage.com' },
    -- Wordpress
    { 0, 506, 'wordpress.org' },
    -- Yahoo!
    { 0, 524, 'yahoo.net' },
    -- 1-800-Flowers
    { 0, 535, '1800flowers.com' },
    -- 2channel
    { 0, 537, '2ch.net' },
    -- 6pm.com
    { 0, 538, '6pm.com' },
    -- Ace Hardware Corporation
    { 0, 539, 'acehardware.com' },
    -- Adobe Software
    { 0, 541, 'adobe.com' },
    -- Adorama
    { 0, 542, 'adorama.com' },
    -- American Express
    { 0, 544, 'americanexpress.ae' },
    { 0, 544, 'americanexpress.ch' },
    -- AOL Mail
    { 0, 546, 'mail.aol.se' },
    -- CC Studios
    --{ 0, 556, 'cc.com' },
    -- Autoblog
    { 0, 557, 'autoblog.com' },
    -- AutoTrader.com
    { 0, 558, 'autotrader.com' },
    -- B&H Photo Video
    { 0, 559, 'bhphotovideo.com' },
    -- Basecamp
    { 0, 563, 'basecamphq.com' },
    -- Best Buy
    { 0, 567, 'bestbuy.com' },
    -- Black & Decker Corporation
    { 0, 572, 'blackanddecker.com' },
    -- Blockbuster
    { 0, 575, 'blockbusteronline.com.br' },
    -- Bloomingdales
    { 0, 577, 'bloomingdales.com' },
    -- Blue Nile
    { 0, 578, 'bluenile.com' },
    -- Bluefly
    { 0, 579, 'bluefly.com' },
    -- CamerasDirect.com.au
    { 0, 581, 'camerasdirect.com.au' },
    -- Capital One
    { 0, 582, 'capitalone.ca' },
    -- Car and Driver
    { 0, 583, 'caranddriver.com' },
    -- CarMax
    { 0, 584, 'carmax.com' },
    -- CDiscount
    { 0, 585, 'cdiscount.com' },
    -- CheapTickets
    { 0, 588, 'cheaptickets.com' },
    -- City Sports
    { 0, 591, 'citysports.com' },
    -- Costco
    { 0, 593, 'costco.ca' },
    -- Craigslist
    { 0, 594, 'craigslist.ca' },
    { 0, 594, 'craigslist.ch' },
    { 0, 594, 'craigslist.de' },
    { 0, 594, 'craigslist.es' },
    { 0, 594, 'craigslist.gr' },
    { 0, 594, 'craigslist.hk' },
    { 0, 594, 'craigslist.it' },
    { 0, 594, 'craigslist.jp' },
    { 0, 594, 'craigslist.pl' },
    { 0, 594, 'craigslist.pt' },
    { 0, 594, 'craigslist.se' },
    -- Crutchfield
    { 0, 595, 'crutchfield.com' },
    -- BitTorrent
    { 0, 61, 'bittorrent.com' },
    -- Diigo
    { 0, 612, 'diigo.com' },
    -- Dillards
    { 0, 613, 'dillards.com' },
    -- Discover
    { 0, 615, 'discoverbank.com' },
    -- Drugstore.com
--    { 0, 620, 'drugstore.com' },
    -- Expedia
    { 0, 628, 'expedia.at' },
    { 0, 628, 'expedia.be' },
    { 0, 628, 'expedia.ca' },
    { 0, 628, 'expedia.de' },
    { 0, 628, 'expedia.dk' },
    { 0, 628, 'expedia.es' },
    { 0, 628, 'expedia.fr' },
    { 0, 628, 'expedia.ie' },
    { 0, 628, 'expedia.it' },
    { 0, 628, 'expedia.nl' },
    { 0, 628, 'expedia.no' },
    { 0, 628, 'expedia.se' },
    -- Fidelity
    { 0, 636, 'fidelity-international.com' },
    { 0, 636, 'fidelity-italia.it' },
    { 0, 636, 'fidelity.at' },
    { 0, 636, 'fidelity.de' },
    { 0, 636, 'fidelity.fr' },
    { 0, 636, 'fidelity.nl' },
    { 0, 636, 'fidelity.se' },
    -- Fnac
    { 0, 640, 'fnac.ch' },
    { 0, 640, 'fnac.com' },
    { 0, 640, 'fnac.es' },
    { 0, 640, 'fnac.pt' },
    -- FTD
    { 0, 644, 'ftd.com' },
    -- { 0, 646, 'g4tv.com' },
    -- Game Informer
    { 0, 647, 'gameinformer.com' },
    -- GameSpy
    { 0, 649, 'gamespy.com' },
    -- GameStop
    { 0, 650, 'gamestop.ca' },
    { 0, 650, 'gamestop.com' },
    { 0, 650, 'gamestop.de' },
    { 0, 650, 'gamestop.dk' },
    { 0, 650, 'gamestop.es' },
    { 0, 650, 'gamestop.fi' },
    { 0, 650, 'gamestop.ie' },
    { 0, 650, 'gamestop.it' },
    { 0, 650, 'gamestop.no' },
    { 0, 650, 'gamestop.pt' },
    { 0, 650, 'gamestop.se' },
    -- GameTrailers
    { 0, 651, 'gametrailers.com' },
    -- Haiku Learning Systems
    { 0, 669, 'haikulearning.com' },
    -- Home Depot
    { 0, 670, 'homedepot.ca' },
    { 0, 670, 'homedepot.com' },
    -- House of Fraser
    { 0, 674, 'houseoffraser.co.uk' },
    -- HSBC
    { 0, 675, 'hsbc.am' },
    { 0, 675, 'hsbc.bm' },
    { 0, 675, 'hsbc.ca' },
    { 0, 675, 'hsbc.fr' },
    { 0, 675, 'hsbc.ge' },
    { 0, 675, 'hsbc.gr' },
    { 0, 675, 'hsbc.lk' },
    { 0, 675, 'hsbctrinkaus.de' },
    -- Hulu
    { 0, 677, 'hulu.com' },
    -- J.C. Penney
    { 0, 690, 'jcpenney.com' },
    -- Jalopnik
    { 0, 693, 'jalopnik.com' },
    -- Joystiq
    { 0, 696, 'joystiq.com' },
    -- Kay Jewelers
    { 0, 698, 'kay.com' },
    -- Kmart
    { 0, 702, 'kmart.com' },
    -- Kogan Technologies
    { 0, 703, 'kogan.co.uk' },
    { 0, 703, 'kogan.com.au' },
    -- Kohl's
    { 0, 704, 'kohls.com' },
    -- Kotaku
    { 0, 707, 'kotaku.com' },
    -- LiveJournal
    { 0, 716, 'livejournal.com' },
    -- Lord & Taylor
    { 0, 719, 'lordandtaylor.com' },
    -- Lowe's
    { 0, 722, 'lowes.ca' },
    { 0, 722, 'lowes.com' },
    -- Menards
    { 0, 727, 'menards.com' },
    -- MetaFilter
    { 0, 729, 'metafilter.com' },
    -- yUdutu
    { 0, 748, 'myudutu.com' },
    -- Neckermann
    -- { 0, 750, 'neck.be' },
    { 0, 750, 'neck.nl' },
    { 0, 750, 'neckermann.at' },
    { 0, 750, 'neckermann.ch' },
    { 0, 750, 'neckermann.com.pl' },
    { 0, 750, 'neckermann.cz' },
    { 0, 750, 'neckermann.de' },
    { 0, 750, 'neckermann.si' },
    -- Neiman Marcus
    { 0, 751, 'neimanmarcus.com' },
    -- tlog
    { 0, 757, 'netlog.com' },
    -- Netvibes
    { 0, 758, 'netvibes.com' },
    -- Newegg
    { 0, 759, 'newegg.ca' },
    { 0, 759, 'newegg.cn' },
    { 0, 759, 'neweggbusiness.com' },
    { 0, 759, 'neweggflash.com' },
    -- NewsNow
    { 0, 760, 'newsnow.co.uk' },
    -- Newsvine
    { 0, 761, 'newsvine.com' },
    -- Noordstrom
    { 0, 764, 'nordstrom.com' },
    -- Office Depot
    { 0, 768, 'office-depot.be' },
    { 0, 768, 'office-depot.ch' },
    { 0, 768, 'office-depot.fr' },
    { 0, 768, 'officedepot.at' },
    { 0, 768, 'officedepot.be' },
    { 0, 768, 'officedepot.ca' },
    { 0, 768, 'officedepot.ch' },
    { 0, 768, 'officedepot.cz' },
    { 0, 768, 'officedepot.de' },
    { 0, 768, 'officedepot.es' },
    { 0, 768, 'officedepot.fr' },
    { 0, 768, 'officedepot.hu' },
    -- { 0, 768, 'officedepot.ie' },
    { 0, 768, 'officedepot.lu' },
    { 0, 768, 'officedepot.sk' },
    -- OfficeMax
    { 0, 769, 'officemax.com' },
    -- Orbitz
    { 0, 775, 'orbitz.com' },
    -- Overstock.com
    { 0, 778, 'overstock.com' },
    -- ProFlowers
    { 0, 793, 'proflowers.com' },
    -- QVC
    { 0, 798, 'qvc.jp' },
    -- Redmine
    { 0, 805, 'redmine.org' },
    -- REI
    { 0, 806, 'rei.com' },
    -- Renren
    { 0, 808, 'renren.com' },
    -- REVOLVEclothing
    { 0, 809, 'revolveclothing.com' },
    -- Rona
    { 0, 810, 'rona.ca' },
    -- Saks Fifth Avenue
    { 0, 816, 'saksfifthavenue.com' },
    -- Sam's Club
    { 0, 817, 'sams.com.mx' },
    { 0, 817, 'samsclub.com' },
    -- schuelerVZ
    { 0, 818, 'schuelervz.net' },
    -- Schwab
    { 0, 819, 'schwab.com' },
    -- Sears
    { 0, 821, 'searsgaragedoors.com' },
    { 0, 821, 'searshardwarestores.com' },
    { 0, 821, 'searshomeapplianceshowroom.com' },
    { 0, 821, 'searshometownstores.com' },
    -- Shoplet
    { 0, 825, 'shoplet.com' },
    -- ShopNBC
    { 0, 826, 'shopnbc.com' },
    -- ShowClix
    { 0, 830, 'showclix.com' },
    -- spin.de
    { 0, 841, 'spin.de' },
    -- Staples
    { 0, 848, 'staples.de' },
    { 0, 848, 'staples.pt' },
    { 0, 848, 'staples.com' },
    -- StayFriends
    { 0, 849, 'stayfriends.de' },
    -- StubHub
    { 0, 850, 'stubhub.com' },
    -- studiVZ
    { 0, 851, 'studivz.net' },
    -- Swarovski
    { 0, 854, 'swarovski.com' },
    -- T. Rowe Price
    { 0, 855, 'troweprice.com' },
    -- Tchibo
    { 0, 859, 'eduscho.at' },
    { 0, 859, 'tchibo.ch' },
    { 0, 859, 'tchibo.com.tr' },
    { 0, 859, 'tchibo.cz' },
    { 0, 859, 'tchibo.de' },
    { 0, 859, 'tchibo.pl' },
    -- TD Ameritrade
    { 0, 860, 'tdameritrade.com' },
    -- The Gap
    { 0, 863, 'gap.cn' },
    { 0, 863, 'gap.co.jp' },
    { 0, 863, 'gap.com' },
    { 0, 863, 'gap.eu' },
    { 0, 863, 'gapcanada.ca' },
    -- The Sharper Image
    { 0, 864, 'sharperimage.com' },
    -- ThinkGeek
--    { 0, 865, 'thinkgeek.com' },
    -- Ticketmaster
    { 0, 867, 'ticketmaster.ca' },
    { 0, 867, 'ticketmaster.com' },
    { 0, 867, 'ticketsnow.com' },
    -- Tickets.com
    { 0, 868, 'tickets.com' },
    -- Tiffany & Co.
    { 0, 870, 'tiffany.at' },
    { 0, 870, 'tiffany.cn' },
    { 0, 870, 'tiffany.de' },
    { 0, 870, 'tiffany.fr' },
    { 0, 870, 'tiffany.it' },
    { 0, 870, 'tiffany.kr' },
    -- Tiger Direct
    { 0, 871, 'tigerdirect.ca' },
    { 0, 871, 'tigerdirect.com' },
    -- Top Gear
    { 0, 877, 'topgear.com' },
    -- Trac
    { 0, 878, 'trac.edgewall.org' },
    -- Travelocity
    { 0, 880, 'travelocity.ca' },
    { 0, 880, 'travelocity.com' },
    -- TripAdvisor
    { 0, 881, 'tripadvisor.com' },
    -- Ustream.tv
    { 0, 884, 'ustream.tv' },
    -- Vanguard
    { 0, 885, 'vanguardinvestments.ch' },
    { 0, 885, 'vanguardinvestments.de' },
    { 0, 885, 'vanguardinvestments.dk' },
    --{ 0, 885, 'vanguardinvestments.fr' },
    { 0, 885, 'vanguardinvestments.nl' },
    { 0, 885, 'vanguardinvestments.se' },
    -- vente-privee.com
    { 0, 888, 'vente-privee.com' },
    -- Vimeo
    { 0, 893, 'vimeo.com' },
    -- Voyages-sncf.com
    { 0, 899, 'voyages-sncf.com' },
    -- Wachovia
--    { 0, 900, 'wachovia.com' },
    -- Web Of Trust
    { 0, 903, 'mywot.com' },
    -- Windows Live SkyDrive
    { 0, 911, 'skydrive.live.com' },
    -- Woot
    { 0, 917, 'woot.com' },
    -- XM Radio Online
    { 0, 923, 'xmradio.com' },
    -- Zales
    { 0, 930, 'zales.com' },
    -- Zappos
    { 0, 931, 'zappos.com' },
    -- tflix stream
    --{ 0, 939, 'netflix.com' },
    -- Yahoo! Toolbar
    { 0, 947, 'toolbar.yahoo.com' },
    -- RitzCamera.com
    { 0, 951, 'ritzcamera.com' },
    -- Macy's
    { 0, 952, 'macys.com' },
    -- 7digital
    { 0, 959, '7digital.com' },
    -- Commvault
    -- { 0, 96, 'commvault.be' },
    -- { 0, 96, 'commvault.ca' },
    { 0, 96, 'commvault.cl' },
    { 0, 96, 'commvault.co.uk' },
    { 0, 96, 'commvault.co.za' },
    { 0, 96, 'commvault.de' },
    { 0, 96, 'commvault.fr' },
    { 0, 96, 'commvault.in' },
    { 0, 96, 'commvault.it' },
    { 0, 96, 'commvault.jp' },
    { 0, 96, 'commvault.nl' },
    { 0, 96, 'commvault.ru' },
    { 0, 96, 'commvault.se' },
    -- Chatroulette
    { 0, 962, 'chatroulette.com' },
    -- Cyworld
    { 0, 963, 'cyworld.co' },
    -- Daum
    { 0, 964, 'daum.net' },
    -- Deezer
    { 0, 965, 'deezer.com' },
    -- Evony
    { 0, 970, 'evony.com' },
    -- FileDropper
    { 0, 971, 'filedropper.com' },
    -- Filemail
    { 0, 972, 'filemail.com' },
    -- Licorize
    { 0, 974, 'licorize.com' },
    -- FORA.tv
    { 0, 976, 'fora.tv' },
    -- Habbo
    { 0, 980, 'habbo.at' },
    { 0, 980, 'habbo.be' },
    { 0, 980, 'habbo.cl' },
    { 0, 980, 'habbo.de' },
    { 0, 980, 'habbo.dk' },
    { 0, 980, 'habbo.fi' },
    { 0, 980, 'habbo.fr' },
    { 0, 980, 'habbo.it' },
    { 0, 980, 'habbo.jp' },
    -- The Hype Machine
    { 0, 982, 'hypem.com' },
    -- iHeartRadio
    { 0, 984, 'iheartradio.com' },
    -- Issuu
    { 0, 985, 'issuu.co' },
    -- Jamendo
    { 0, 986, 'jamendo.com' },
    -- Livestream
    { 0, 991, 'livestream.com' },
    -- MyDownloader
    { 0, 995, 'mydownloader.net' },
    -- Omegle
    { 0, 997, 'omegle.com' },
    -- Mister Wong
    { 0, 999, 'mister-wong.com' },
    { 0, 999, 'mister-wong.de' },
    { 0, 999, 'mister-wong.es' },
    { 0, 999, 'mister-wong.fr' },
    -- ESPN Video
    { 0, 2933, 'media.video-cdn.espn.com' },
    { 0, 2933, 'watch-cdn.product.api.espn.com' },

}

gSSLCnamePatternList = {

    -- Blizzard
    { 0, 3745, 'cnc.blzstatic', },

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end


