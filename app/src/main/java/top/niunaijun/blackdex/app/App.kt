package top.niunaijun.blackdex.app

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import com.orhanobut.logger.AndroidLogAdapter
import com.orhanobut.logger.Logger
import com.umeng.commonsdk.UMConfigure




/**
 *
 * @Description:
 * @Author: wukaicheng
 * @CreateDate: 2021/4/29 21:21
 */
class App : Application() {

    companion object {

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private lateinit var mContext: Context

        @JvmStatic
        fun getContext(): Context {
            return mContext
        }
    }

    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base)
        mContext = base!!
        AppManager.doAttachBaseContext(base)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    override fun onCreate() {
        Logger.addLogAdapter(AndroidLogAdapter())
        super.onCreate()
        AppManager.doOnCreate(mContext)
//        UMConfigure.init(this, "60b373136c421a3d97d23c29", "Github", UMConfigure.DEVICE_TYPE_PHONE, null)

        // 获取并打印当前进程名称
        val processName = getProcessName()
        Logger.d("onCreate 当前进程: $processName")
    }
}