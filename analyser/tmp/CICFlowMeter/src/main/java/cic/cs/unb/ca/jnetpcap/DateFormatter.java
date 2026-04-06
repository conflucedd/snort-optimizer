package cic.cs.unb.ca.jnetpcap;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class DateFormatter {
	
	public static String parseDateFromLong(long time, String format){
		try{
			if (format == null){
				format = "dd/MM/yyyy hh:mm:ss";					
			}
			SimpleDateFormat simpleFormatter = new SimpleDateFormat(format);
			Date tempDate = new Date(time);
			return simpleFormatter.format(tempDate);
		}catch(Exception ex){
			System.out.println(ex.toString());
			return "dd/MM/yyyy hh:mm:ss";
		}		
	}

	public static String convertMilliseconds2String(long time, String format) {

        if (format == null){
            format = "dd/MM/yyyy hh:mm:ss";
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
        return ldt.format(formatter);
	}

	public static String convertMicroseconds2String(long time, String format) {
		if (format == null) {
			format = "yyyy-MM-dd HH:mm:ss.SSSSSS";
		}

		long seconds = Math.floorDiv(time, 1_000_000L);
		long micros = Math.floorMod(time, 1_000_000L);
		Instant instant = Instant.ofEpochSecond(seconds, micros * 1_000L);
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneId.systemDefault())
				.truncatedTo(ChronoUnit.MICROS);
		return DateTimeFormatter.ofPattern(format).format(ldt);
	}

}
