package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.LINE_SEP;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};

    public static void main(String[] args) {

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String pcapPath;
        String outPath;

        if (args.length != 2) {
            printUsage();
            return;
        }
        pcapPath = args[0];
        File in = new File(pcapPath);

        if (!in.exists()) {
            logger.info("The pcap file does not exist! -> {}",pcapPath);
            return;
        }

        outPath = args[1];

        if (!isPcapFile(in)) {
            logger.info("Please select a .pcap file! -> {}", pcapPath);
            return;
        }

        File out = resolveOutputFile(outPath);
        if (out == null) {
            return;
        }

        logger.info("Input pcap: {}",pcapPath);
        logger.info("Output csv: {}",out.getPath());

        logger.info("CICFlowMeter received 1 pcap file");
        readPcapFile(in.getPath(), out,flowTimeout,activityTimeout);
    }

    private static void printUsage() {
        logger.info("Usage: java ... cic.cs.unb.ca.ifm.Cmd <input.pcap> <output.csv>");
    }

    private static void readPcapFile(String inputFile, File saveFileFullPath, long flowTimeout, long activityTimeout) {
        if(inputFile==null || saveFileFullPath==null ) {
            return;
        }
        String fileName = FilenameUtils.getName(inputFile);

        if (saveFileFullPath.exists()) {
           if (!saveFileFullPath.delete()) {
               System.out.println("Save file can not be deleted");
           }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName, saveFileFullPath));
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

        private File outputFile;

        private long cnt;

        public FlowListener(String fileName, File outputFile) {
            this.fileName = fileName;
            this.outputFile = outputFile;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {

            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            insertRows(FlowFeature.getHeader(), flowStringList, outputFile);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName,cnt);

            System.out.print(console);
        }
    }

    private static File resolveOutputFile(String outPath) {
        File out = new File(outPath);

        if (out.exists() && out.isDirectory()) {
            logger.info("Output must be a csv file path, not a directory! -> {}", outPath);
            return null;
        }

        if (!outPath.toLowerCase().endsWith(".csv")) {
            logger.info("Output path must end with .csv! -> {}", outPath);
            return null;
        }

        File parent = out.getParentFile();
        if (parent != null && !parent.exists()) {
            if (!parent.mkdirs()) {
                logger.info("Output directory can not be created! -> {}", parent.getPath());
                return null;
            }
        }

        return out;
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

    private static void insertRows(String header, List<String> rows, File file) {
        if (file == null || rows == null || rows.size() <= 0) {
            String ex = String.format("file=%s", file);
            throw new IllegalArgumentException(ex);
        }

        FileOutputStream output = null;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (!file.createNewFile()) {
                    logger.debug("Output csv can not be created: {}", file.getPath());
                    return;
                }
                output = new FileOutputStream(file);
                if (header != null) {
                    output.write((header + LINE_SEP).getBytes());
                }
            }

            for (String row : rows) {
                output.write((row + LINE_SEP).getBytes());
            }
        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
    }

}
