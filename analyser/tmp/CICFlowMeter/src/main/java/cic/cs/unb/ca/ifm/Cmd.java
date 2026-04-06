package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.Sys.FILE_SEP;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};

    public static void main(String[] args) {

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String pcapPath;
        String outPath;

        if (args.length < 1) {
            printUsage();
            return;
        }
        pcapPath = args[0];
        File in = new File(pcapPath);

        if (!in.exists()) {
            logger.info("The pcap file does not exist! -> {}",pcapPath);
            return;
        }

        if (args.length < 2) {
            printUsage();
            return;
        }
        outPath = args[1];

        if (!isPcapFile(in)) {
            logger.info("Please select a .pcap file! -> {}", pcapPath);
            return;
        }

        logger.info("Input pcap: {}",pcapPath);
        logger.info("Output target: {}",outPath);

        logger.info("CICFlowMeter received 1 pcap file");
        readPcapFile(in.getPath(), outPath,flowTimeout,activityTimeout);
    }

    private static void printUsage() {
        logger.info("Usage: java ... cic.cs.unb.ca.ifm.Cmd <input.pcap> <output.csv|output_dir>");
    }

    private static void readPcapFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if(inputFile==null ||outPath==null ) {
            return;
        }
        String fileName = FilenameUtils.getName(inputFile);
        File saveFileFullPath = resolveOutputFile(fileName, outPath);

        if (saveFileFullPath.exists()) {
           if (!saveFileFullPath.delete()) {
               System.out.println("Save file can not be deleted");
           }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName,outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s",fileName));

        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        int i=0;
        while(true) {
            /*i = (i)%animationChars.length;
            System.out.print("Working on "+ inputFile+" "+ animationChars[i] +"\r");*/
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket !=null){
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }else{
                    nDiscarded++;
                }
            }catch(PcapClosedException e){
                break;
            }
            i++;
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

        long lines = countLines(saveFileFullPath);

        System.out.println(String.format("%s is done. total %d flows ",fileName,lines));
        System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d",nTotal,nValid,nDiscarded));
        System.out.println(DividingLine);

        //long end = System.currentTimeMillis();
        //logger.info(String.format("Done! in %d seconds",((end-start)/1000)));
        //logger.info(String.format("\t Total packets: %d",nTotal));
        //logger.info(String.format("\t Valid packets: %d",nValid));
        //logger.info(String.format("\t Ignored packets:%d %d ", nDiscarded,(nTotal-nValid)));
        //logger.info(String.format("PCAP duration %d seconds",((packetReader.getLastPacket()- packetReader.getFirstPacket())/1000)));
        //int singleTotal = flowGen.dumpLabeledFlowBasedFeatures(outPath, fileName+ FlowMgr.FLOW_SUFFIX, FlowFeature.getHeader());
        //logger.info(String.format("Number of Flows: %d",singleTotal));
        //logger.info("{} is done,Total {} flows",inputFile,singleTotal);
        //System.out.println(String.format("%s is done,Total %d flows", inputFile, singleTotal));
    }

    static class FlowListener implements FlowGenListener {

        private String fileName;

        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {

            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(),flowStringList,outPath,fileName+ FlowMgr.FLOW_SUFFIX);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName,cnt);

            System.out.print(console);
        }
    }

    private static File resolveOutputFile(String inputFileName, String outPath) {
        File out = new File(outPath);
        if (outPath.toLowerCase().endsWith(".csv")) {
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            return out;
        }

        if (out.exists() && out.isDirectory()) {
            return new File(out, inputFileName + FlowMgr.FLOW_SUFFIX);
        }

        if (outPath.endsWith(FILE_SEP)) {
            return new File(outPath + inputFileName + FlowMgr.FLOW_SUFFIX);
        }

        if (out.exists()) {
            return out;
        }

        File parent = out.getParentFile();
        if (parent != null) {
            if (!parent.exists()) {
                parent.mkdirs();
            }
            return out;
        }

        out.mkdirs();
        return new File(out, inputFileName + FlowMgr.FLOW_SUFFIX);
    }

    private static boolean isPcapFile(File file) {
        return file.isFile() && file.getName().toLowerCase().endsWith(".pcap");
    }

    private static long countLines(File file) {
        java.io.BufferedReader reader = null;
        long count = 0L;
        try {
            reader = new java.io.BufferedReader(new java.io.FileReader(file));
            while (reader.readLine() != null) {
                count++;
            }
        } catch (java.io.IOException e) {
            logger.debug(e.getMessage());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (java.io.IOException e) {
                    logger.debug(e.getMessage());
                }
            }
        }
        return count > 0 ? count - 1 : 0;
    }

}
