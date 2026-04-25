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
detection_name: Payload Group "drdre"
version: 6
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Daum Mail' => 'Daum webmail.',
          'Naver Cafe' => 'Naver forums and social networking.',
          'Naver Mail' => 'Naver webmail.',
          'Edge' => 'Microsoft web browser.',
          'Naver Blog' => 'Naver blogging app.',
          'Internet Explorer' => 'A Microsoft web browser.',
          'Daum Cafe' => 'Daum forums and social networking.',
          'Daum Blog' => 'Daum blogging app.',
          'Kakao Story' => 'Keeping blogs on Kakao.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_drdre",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Naver Blog
    { 0, 0, 0, 1839, 5, "blog.naver.com", "/", "http:", "", 4050},
    -- { 0, 0, 0, 1839, 5, "blog.naver.net", "/", "http:", "", 4050},
    -- { 0, 0, 0, 1839, 5, "blog.poll.naver.com", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "naverblogwidget.com", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "mblogthumb4.phinf.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogfiles13.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogimgs.naver.com", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "static.naver.net", "/blog", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogfiles5.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogfiles4.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogpfthumb.phinf.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogimgs.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogthumb2.naver.net", "/", "http:", "", 4050},
    { 0, 0, 0, 1839, 5, "blogfiles9.naver.net", "/", "http:", "", 4050},
    -- Naver Cafe
    { 0, 0, 0, 1840, 5, "cafe.naver.com", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "cafefiles.naver.net", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "cafeimgs.naver.net", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "cafeptthumb3.phinf.naver.net", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "cafeptthumb2.phinf.naver.net", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "cafeptthumb1.phinf.naver.net", "/", "http:", "", 4051},
    -- { 0, 0, 0, 1840, 5, "cafeptthumb4.phinf.naver.net", "/", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "lcs.naver.com", "cafe", "http:", "", 4051},
    { 0, 0, 0, 1840, 5, "static.naver.net", "/cafe", "http:", "", 4051},
    -- Daum Blog
    { 0, 0, 0, 1841, 5, "blog.daum.net", "/", "http:", "", 4052},
    -- Daum Cafe
    { 0, 0, 0, 1842, 5, "cafe.daum.net", "/", "http:", "", 4053},
    { 0, 0, 0, 1842, 5, "cafeimg.daum-img.net", "/", "http:", "", 4053},
    -- Naver Mail
    { 0, 0, 0, 1843, 4, "mail.naver.com", "/", "http:", "", 4054},
    { 0, 0, 0, 1843, 4, "static.naver.net", "/mail", "http:", "", 4054},
    -- Daum Mail
    { 0, 0, 0, 1844, 4, "mail.daum.net", "/", "http:", "", 4055},
    { 0, 0, 0, 1844, 4, "mail1.daumcdn.net", "/", "http:", "", 4055},
    -- Kakao Story
    { 0, 0, 0, 1845, 5, "story.kakao.com", "/", "http:", "", 4056},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    --Internet Explorer (for IE 11)
    gDetector:addHttpPattern(2, 5, 0, 1, 1, 0, 0, 'Trident/7.0;', 686, 1);

    -- Microsoft Edge
    gDetector:addHttpPattern(2, 5, 0, 506, 1, 0, 0, 'Edge/', 4057, 1);
    gDetector:addHttpPattern(2, 5, 0, 506, 1, 0, 0, 'EdgA/', 4057, 1);
    gDetector:addHttpPattern(2, 5, 0, 506, 1, 0, 0, 'EdgiOS/', 4057, 1);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()

end
