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
detection_name: SSL Group Full "334 part2"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Yellow Pages' => 'Online directory and Mapping services.',
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Sears' => 'Department store retailer.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'Intuit' => 'Software company for financial and tax related services.',
          'YY' => 'Chinese Chat application.',
          'UOL' => 'Brazilian web portal for news and entertainment.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'Moat' => 'Ad search and analystics.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'Al Jazeera' => 'News network based in the Arab world.',
          'Newegg' => 'Computer hardware and software retailer.',
          'CareerBuilder.com' => 'Online job search portal.',
          'Disney' => 'Official Disney website.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'GameStop' => 'Video game retailer.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'Wikia' => 'Web portal to contribute and share the knowledge.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'HSBC' => 'Global banking and financial services company.',
          'EarthLink' => 'IT Solution provider for network and communications.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'Office Depot' => 'Office supply retailer.',
          'Neckermann' => 'General goods online retailer.',
          'Verizon' => 'Internet, TV and Phone service provider.',
          'InsightExpress' => 'Analyser for online and Mobile advertisements.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.',
          'InSkin Media' => 'Advertisement site.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          'Vanguard' => 'Investment management company.',
          'BBC' => 'Web Portal for news update.',
          'American Express' => 'Financial services company.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  'ssl_host_group_full_334_part2',
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLCnamePatternList = {
    -- Webhard
      { 0, 1020, 'webhard.net' },
    -- CanvasRider
    --{ 0, 1361, 'bonoboplanet-jeu.com' },
    -- Afreeca
      { 0, 1037, 'afreecatv.com' },
    -- InsightExpress
      { 0, 1461, 'insightexpressai.com' },
    -- Wikia
      { 0, 1485, 'wikia.nocookie.net' },
    -- Yellow Pages
      { 0, 1497, 'yellowpages.in' },
    -- EarthLink
      { 0, 1514, 'earthlinkbusiness.com' },
    -- Disney
      { 0, 1515, 'disney.co.uk' },
    -- Intuit
      { 0, 1526, 'intuitstatic.com' },
    -- Alisoft
    -- UOL
      { 0, 1626, 'imguol.com' },
    -- YY
      { 0, 1663, 'hiido.com' },
    -- NBC
      { 0, 1988, 'murtl.nbcudps.com' },
      { 0, 1988, 'nbcuni.com' },
    -- Speedtest
      { 0, 2103, 'speedtest.centurylink.net' },
    -- Al Jazeera
      { 0, 2180, 'aljazeera.net' },
    -- IKEA.com
      { 0, 2349, 'ikea.is' },
    -- InSkin Media
      { 0, 2527, 'inskinad.com' },
    -- Moat
      { 0, 2664, 'moatads.com' },
    -- BBC
      { 0, 1376, 'bbcpreview.com' },
      { 0, 1376, 'bbc.com' },
    -- Wall Street Journal                                                                          
    { 0, 1390, 'efinancialcareers.com' },
    -- American Express
      { 0, 544, 'americanexpress.ch' },
    -- Fidelity
      { 0, 636, 'www.fidelityinternational.com' },
    -- Fnac
      { 0, 640, 'www.fnac.es' },
      { 0, 640, 'www.fnac.pt' },
      { 0, 640, 'www.fr.fnac.ch' },
    -- GameStop
      { 0, 650, 'gamestop.ie' },
    -- Home Depot
      { 0, 670, 'www.homedepot.ca' },
    -- HSBC
      { 0, 675, 'www.hsbc.am' },
      { 0, 675, 'www.hsbc.bm' },
      { 0, 675, 'www.hsbc.fr' },
      { 0, 675, 'www.hsbc.gr' },
      { 0, 675, 'www.hsbc.lk' },
      { 0, 675, 'www.hsbctrinkaus.de' },
    -- Lord & Taylor
    -- Neckermann
      { 0, 750, 'www.neckermann.de' },
    -- Newegg
      { 0, 759, 'newegg.cn' },
      --{ 0, 759, 'newegg.io' },
    -- Verizon                                                                                      
      { 0, 1484, 'can.transactcdn.com' },
    -- CareerBuilder.com                                                                            
      { 0, 1491, 'caresouthcareers.co.uk' },
    -- Office Depot
      { 0, 768, 'officedepot.hu' },
      { 0, 768, 'officedepot.sk' },
      { 0, 768, 'origin-prd.officedepot.eu' },
      { 0, 768, 'www.grandandtoy.com' },
      { 0, 768, 'www.officedepot.cz' },
    -- Sam's Club
      { 0, 817, 'origin-www.sams.com.mx' },
    -- Sears
      { 0, 821, 'club.ourvacationcenter.com' },
    -- Tchibo
      { 0, 859, 'tchibo.ch' },
      { 0, 859, 'tchibo.com.tr' },
      { 0, 859, 'tchibo.cz' },
      { 0, 859, 'tchibo.de' },
      { 0, 859, 'tchibo.pl' },
    -- The Gap
      { 0, 863, 'www.gap.eu' },
    -- Tiffany & Co.                                                                                
     --{ 0, 870, 'origin-ecom-az.tiffany.cn' },
      { 0, 870, 'tiffany.cn' },
    -- Vanguard
      { 0, 885, 'vanguardinvestments.ch' },
      { 0, 885, 'vanguardinvestments.de' },
      { 0, 885, 'vanguardinvestments.dk' },
      { 0, 885, 'vanguardinvestments.fr' },
      { 0, 885, 'vanguardinvestments.nl' },
      { 0, 885, 'vanguardinvestments.se' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end


