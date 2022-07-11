package com.clostra.newnode.vpn;

import android.content.Context;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;

public class BlinkAnimation {
    private final View view;
    private final Animation fadeIn;
    private final Animation fadeOut;

    BlinkAnimation(Context context, View view, Runnable onFadeOutEnd) {
        this.view = view;

        fadeIn = AnimationUtils.loadAnimation(context, R.anim.fade_in);
        fadeIn.setDuration(500);
        fadeOut = AnimationUtils.loadAnimation(context, R.anim.fade_out);
        fadeOut.setDuration(500);

        fadeIn.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });

        fadeOut.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                onFadeOutEnd.run();
                view.startAnimation(fadeIn);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });
    }

    public void start() {
        view.startAnimation(fadeOut);
    }
}
