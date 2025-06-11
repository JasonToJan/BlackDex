package top.niunaijun.blackbox.fake.frameworks;

import android.content.Intent;
import android.os.RemoteException;

import com.orhanobut.logger.Logger;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.system.ServiceManager;
import top.niunaijun.blackbox.core.system.am.IBActivityManagerService;

/**
 * Created by Milk on 4/14/21.
 * * ∧＿∧
 * (`･ω･∥
 * 丶　つ０
 * しーＪ
 * 此处无Bug
 */
public class BActivityManager {
    private static final BActivityManager sActivityManager = new BActivityManager();
    private IBActivityManagerService mService;

    public static BActivityManager get() {
        return sActivityManager;
    }

    public void startActivity(Intent intent, int userId) {
        try {
            getService().startActivity(intent, userId);
            Logger.d("startActivity success...");
        } catch (Exception e) {
            e.printStackTrace();
            Logger.d("startActivity error..."+e.getMessage());
        }
    }

    private IBActivityManagerService getService() {
        if (mService != null && mService.asBinder().isBinderAlive()) {
            return mService;
        }
        mService = IBActivityManagerService.Stub.asInterface(BlackBoxCore.get().getService(ServiceManager.ACTIVITY_MANAGER));
        Logger.d("mService success..."+mService+" alive="+mService.asBinder().isBinderAlive());
        return getService();
    }
}
