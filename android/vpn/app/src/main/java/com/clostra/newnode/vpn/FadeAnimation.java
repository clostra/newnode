package com.clostra.newnode.vpn;

import android.content.Context;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;

public class FadeAnimation {
    private final View view;
    private final Animation fadeIn;
    private final Animation fadeOut;

    FadeAnimation(Context context, View view) {
        this.view = view;

        fadeIn = AnimationUtils.loadAnimation(context, R.anim.fade_in);
        fadeOut = AnimationUtils.loadAnimation(context, R.anim.fade_out);

        fadeIn.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                view.setVisibility(View.VISIBLE);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });

        fadeOut.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                view.setVisibility(View.GONE);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });
    }

    public void fadeIn() {
        fadeIn(0);
    }

    public void fadeOut() {
        fadeOut(0);
    }

    public void fadeIn(int delay) {
        fadeIn.setStartOffset(delay);
        view.startAnimation(fadeIn);
    }

    public void fadeOut(int delay) {
        fadeOut.setStartOffset(delay);
        view.startAnimation(fadeOut);
    }
}
