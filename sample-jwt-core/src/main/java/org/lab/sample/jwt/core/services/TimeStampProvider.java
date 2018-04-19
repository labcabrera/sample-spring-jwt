package org.lab.sample.jwt.core.services;

import java.util.Calendar;
import java.util.Date;

import org.springframework.stereotype.Service;

@Service
public class TimeStampProvider {

	public Date getCurrentDate() {
		return Calendar.getInstance().getTime();
	}

}
