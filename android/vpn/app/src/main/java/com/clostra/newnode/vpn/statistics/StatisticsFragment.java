package com.clostra.newnode.vpn.statistics;

import android.graphics.Typeface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.clostra.newnode.vpn.R;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Calendar;

public class StatisticsFragment extends Fragment {
    public StatisticsFragment() {
        super(R.layout.statistics_fragment);
    }

    private View layout;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {

        View view = inflater.inflate(R.layout.statistics_fragment, container, false);

        layout = view;
        updateDataVolume(layout.findViewById(R.id.statistic_timeframe_day), TimeFrame.DAY);

        layout.findViewById(R.id.statistic_timeframe_day).setOnClickListener( v -> updateDataVolume((TextView) v, TimeFrame.DAY));
        layout.findViewById(R.id.statistic_timeframe_week).setOnClickListener( v -> updateDataVolume((TextView) v, TimeFrame.WEEK));
        layout.findViewById(R.id.statistic_timeframe_all_time).setOnClickListener( v -> updateDataVolume((TextView) v, TimeFrame.ALL_TIME));

        return view;
    }

    private void resetTypeFaceToStatisticToggle() {
        ((TextView) layout.findViewById(R.id.statistic_timeframe_day)).setTypeface(Typeface.DEFAULT);
        ((TextView) layout.findViewById(R.id.statistic_timeframe_week)).setTypeface(Typeface.DEFAULT);
//        ((TextView) layout.findViewById(R.id.statistic_timeframe_month)).setTypeface(Typeface.DEFAULT);
//        ((TextView) layout.findViewById(R.id.statistic_timeframe_year)).setTypeface(Typeface.DEFAULT);
        ((TextView) layout.findViewById(R.id.statistic_timeframe_all_time)).setTypeface(Typeface.DEFAULT);
    }

    public long getTimeStartMillis(TimeFrame timeFrame) {
        Calendar calendar = Calendar.getInstance();
        switch (timeFrame) {
            case DAY:
                break;
            case WEEK:
                calendar.set(Calendar.DAY_OF_WEEK, Calendar.MONDAY);
                break;
            case MONTH:
                calendar.set(Calendar.DAY_OF_MONTH, 1);
                break;
            case YEAR:
                calendar.set(Calendar.DAY_OF_YEAR, 1);
                break;
            case ALL_TIME:
                calendar.set(Calendar.YEAR, 2020);
                calendar.set(Calendar.DAY_OF_YEAR, 1);
        }

        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);

        return calendar.getTimeInMillis();
    }

    private DataVolume getDataVolumeFromTimeFrame(TimeFrame timeFrame) {
        long millis = getTimeStartMillis(timeFrame);
        // todo: return some like VpnService.getDataVolume(millis);
        // Service must return DataVolume for timeframe from millis to current time

        long volume = System.currentTimeMillis() - millis;
        return new DataVolume(volume, volume / 2);
    }

    public static double floor(double value) {
        BigDecimal bd = BigDecimal.valueOf(value);
        bd = bd.setScale(2, RoundingMode.FLOOR);
        return bd.doubleValue();
    }

    private String dateVolumeToString (double bytes) {
        String str;
        long k = 1000L;
        long m = k * k;
        long g = k * k * k;
        long t = k * k * k * k;

        if (bytes < 100) {
            str = floor(bytes) + getResources().getString(R.string.statistic_byte);
        } else if (bytes < 100 * k) {
            str = floor(bytes / k) + getResources().getString(R.string.statistic_kilo_byte);
        } else if (bytes < 100 * m) {
            str = floor(bytes / m) + getResources().getString(R.string.statistic_mega_byte);
        } else if (bytes < 100 * g) {
            str = floor(bytes / g) + getResources().getString(R.string.statistic_giga_byte);
        } else {
            str = floor(bytes / t) + getResources().getString(R.string.statistic_tera_byte);
        }

        return str;
    }

    private void updateDataVolume(TextView view, TimeFrame timeFrame) {
        resetTypeFaceToStatisticToggle();
        view.setTypeface(Typeface.DEFAULT_BOLD);

        DataVolume data = getDataVolumeFromTimeFrame(timeFrame);
        ((TextView) layout.findViewById(R.id.statistic_direct_connections))
                .setText(getResources().getString(R.string.statistic_direct_connections, dateVolumeToString(data.getDirect())));

        ((TextView) layout.findViewById(R.id.statistic_peer_connections))
                .setText(getResources().getString(R.string.statistic_peer_connections, dateVolumeToString(data.getPeer())));
    }
}
