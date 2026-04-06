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
detection_name: Payload Group Full "UB40"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Google Translate' => 'Google translation service.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_full_ub40",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- Google Translate
      { 0, 0, 0, 1295, 22, "translate.google.ac", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ad", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ae", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.af", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ag", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ai", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.al", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.am", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ao", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ar", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.as", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.at", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.au", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.az", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ba", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bd", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.be", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bf", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bh", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bi", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bj", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bo", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.br", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bs", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bw", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.by", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.bz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ca", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.kh", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cc", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cd", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cf", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cat", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ch", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ci", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ck", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.co", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cv", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cy", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.cz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.de", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.dj", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.dk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.dm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.do", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.dz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ec", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ee", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.eg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.es", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.et", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.fi", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.fj", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.fm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.fr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ga", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ge", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gf", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gh", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gi", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gp", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.gy", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.hk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.hn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.hr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ht", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.hu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.id", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.iq", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ie", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.il", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.im", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.in", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.io", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.is", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.it", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.je", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.jm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.jo", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.jp", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ke", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ki", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.kg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.kr", "/", "http:", "", 185},
      --{ 0, 0, 0, 1295, 22, "translate.google.kw", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.kz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.la", "/", "http:", "", 185},
      --{ 0, 0, 0, 1295, 22, "translate.google.lb", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.lc", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.li", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.lk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ls", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.lt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.lu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.lv", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ly", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ma", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.md", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.me", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ml", "/", "http:", "", 185},
      --{ 0, 0, 0, 1295, 22, "translate.google.mm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ms", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mv", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mw", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mx", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.my", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.mz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.na", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ne", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.nf", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ng", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ni", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.nl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.no", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.np", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.nr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.nu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.nz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.om", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pa", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pe", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ph", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ps", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.pt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.py", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.qa", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ro", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.rs", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ru", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.rw", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sa", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sb", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sc", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.se", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sh", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.si", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.so", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.st", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.sr", "/", "http:", "", 185},
      --{ 0, 0, 0, 1295, 22, "translate.google.sv", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.td", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.th", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tj", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tl", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.to", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tr", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tt", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tw", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.tz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ua", "/", "http:", "", 185},
      --{ 0, 0, 0, 1295, 22, "translate.google.ug", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.uk", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.us", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.uy", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.uz", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.vc", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ve", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.vg", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.vi", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.vn", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.vu", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.ws", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.za", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.zm", "/", "http:", "", 185},
      { 0, 0, 0, 1295, 22, "translate.google.zw", "/", "http:", "", 185},
}


function DetectorInit(detectorInstance)
-- ClientType, DHPSequence,  serviceId, clientId, PayloadId,  hostPattern, pathPattern, schemePattern, queryPattern
    gDetector = detectorInstance;
  
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
