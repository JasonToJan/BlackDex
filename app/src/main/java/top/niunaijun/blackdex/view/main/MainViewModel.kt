package top.niunaijun.blackdex.view.main

import androidx.lifecycle.MutableLiveData
import com.orhanobut.logger.Logger
import top.niunaijun.blackdex.data.DexDumpRepository
import top.niunaijun.blackdex.data.entity.AppInfo
import top.niunaijun.blackdex.data.entity.DumpInfo
import top.niunaijun.blackdex.view.base.BaseViewModel

/**
 *
 * @Description:
 * @Author: wukaicheng
 * @CreateDate: 2021/5/23 14:29
 */
class MainViewModel(private val repo: DexDumpRepository) : BaseViewModel() {

    val mAppListLiveData = MutableLiveData<List<AppInfo>>()

    val mDexDumpLiveData = MutableLiveData<DumpInfo>()


    fun getAppList() {
        launchOnUI {
            repo.getAppList(mAppListLiveData)
        }
    }

    fun startDexDump(source: String) {
        Logger.d("开始脱壳==>${source}")
        launchOnUI {
            repo.dumpDex(source, mDexDumpLiveData)
        }
    }

    fun dexDumpSuccess() {
        launchOnUI {
            repo.dumpSuccess()
        }
    }

}