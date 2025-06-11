package top.niunaijun.blackbox.app;

import android.app.Application;
import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.os.Build;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import com.orhanobut.logger.Logger;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import reflection.android.app.ActivityThread;
import reflection.android.app.ContextImpl;
import reflection.android.app.LoadedApk;
import top.niunaijun.blackbox.core.IBActivityThread;
import top.niunaijun.blackbox.core.VMCore;
import top.niunaijun.blackbox.entity.AppConfig;
import top.niunaijun.blackbox.core.IOCore;
import top.niunaijun.blackbox.entity.dump.DumpResult;
import top.niunaijun.blackbox.utils.FileUtils;
import top.niunaijun.blackbox.utils.Slog;
import top.niunaijun.blackbox.BlackBoxCore;

public class BActivityThread extends IBActivityThread.Stub {
    public static final String TAG = "BActivityThread";

    private static BActivityThread sBActivityThread;
    private AppBindData mBoundApplication;
    private Application mInitialApplication;
    private AppConfig mAppConfig;
    private final List<ProviderInfo> mProviders = new ArrayList<>();

    // 环境伪装标志
    private static boolean sEnvironmentSpoofed = false;

    public static BActivityThread currentActivityThread() {
        if (sBActivityThread == null) {
            synchronized (BActivityThread.class) {
                if (sBActivityThread == null) {
                    sBActivityThread = new BActivityThread();
                }
            }
        }
        return sBActivityThread;
    }

    public static synchronized AppConfig getAppConfig() {
        return currentActivityThread().mAppConfig;
    }

    public static List<ProviderInfo> getProviders() {
        return currentActivityThread().mProviders;
    }

    public static String getAppProcessName() {
        if (getAppConfig() != null) {
            return getAppConfig().processName;
        } else if (currentActivityThread().mBoundApplication != null) {
            return currentActivityThread().mBoundApplication.processName;
        } else {
            return null;
        }
    }

    public static String getAppPackageName() {
        if (getAppConfig() != null) {
            return getAppConfig().packageName;
        } else if (currentActivityThread().mInitialApplication != null) {
            return currentActivityThread().mInitialApplication.getPackageName();
        } else {
            return null;
        }
    }

    public static Application getApplication() {
        return currentActivityThread().mInitialApplication;
    }

    public static int getAppPid() {
        return getAppConfig() == null ? -1 : getAppConfig().bpid;
    }

    public static int getAppUid() {
        return getAppConfig() == null ? 10000 : getAppConfig().buid;
    }

    public static int getBaseAppUid() {
        return getAppConfig() == null ? 10000 : getAppConfig().baseBUid;
    }

    public static int getUid() {
        return getAppConfig() == null ? -1 : getAppConfig().uid;
    }

    public static int getUserId() {
        return getAppConfig() == null ? 0 : getAppConfig().userId;
    }

    public void initProcess(AppConfig appConfig) {
        if (this.mAppConfig != null) {
            throw new RuntimeException("reject init process: " + appConfig.processName + ", this process is : " + this.mAppConfig.processName);
        }
        this.mAppConfig = appConfig;
    }

    public boolean isInit() {
        return mBoundApplication != null;
    }

    // 环境伪装（用反射，不用hook框架）
    private void setupFakeEnvironmentWithReflection() {
        if (sEnvironmentSpoofed) return;

        Logger.d("Setting up fake environment with reflection...");
        try {

            // 修改 SystemProperties
            modifySystemProperties();

            // 设置环境变量
            setEnvironmentVariables();

            sEnvironmentSpoofed = true;
            Logger.d("Fake environment setup completed with reflection");
        } catch (Exception e) {
            Logger.e("Failed to setup fake environment: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 反射修改 android.os.Build 的 TYPE 和 TAGS 字段
    private void modifyBuildFields() {
        try {
            Class<?> buildClass = Build.class;
            setStaticField(buildClass, "TYPE", "user");
            setStaticField(buildClass, "TAGS", "release-keys");
            Logger.d("Build fields modified");
        } catch (Exception e) {
            Logger.e("Failed to modify Build fields: " + e.getMessage());
        }
    }

    // 反射修改 SystemProperties
    private void modifySystemProperties() {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method setMethod = systemPropertiesClass.getDeclaredMethod("set", String.class, String.class);
            setMethod.setAccessible(true);

            Map<String, String> safeProperties = new HashMap<>();
            safeProperties.put("ro.debuggable", "0");
            safeProperties.put("ro.build.type", "user");
            safeProperties.put("ro.build.tags", "release-keys");
            safeProperties.put("service.adb.root", "0");
            safeProperties.put("ro.secure", "1");
            safeProperties.put("ro.allow.mock.location", "0");

            for (Map.Entry<String, String> entry : safeProperties.entrySet()) {
                try {
                    setMethod.invoke(null, entry.getKey(), entry.getValue());
                } catch (Exception e) {
                    Logger.w("Failed to set property " + entry.getKey() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            Logger.e("Failed to modify system properties: " + e.getMessage());
        }
    }

    // 反射设置环境变量
    private void setEnvironmentVariables() {
        try {
            Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");
            Field theEnvironmentField = processEnvironment.getDeclaredField("theEnvironment");
            theEnvironmentField.setAccessible(true);

            Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
            if (env != null) {
                env.put("ANDROID_BUILD_TYPE", "user");
            }
            Logger.d("Environment variables modified");
        } catch (Exception e) {
            Logger.e("Failed to modify environment variables: " + e.getMessage());
        }
    }

    // 工具：反射设置静态字段
    private void setStaticField(Class<?> clazz, String fieldName, Object value) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
            field.set(null, value);
        } catch (Exception e) {
            Logger.e("Failed to set static field " + fieldName + ": " + e.getMessage());
        }
    }

// ... 后面还有 PackageContext/LoadedApk/ClassLoader 工具方法和 handleBindApplication 主流程 ...
// 安全地创建PackageContext
private Context createPackageContextSafely(ApplicationInfo info) {
    Context packageContext = null;

    try {
        Logger.d("Creating package context for: " + info.packageName);
        packageContext = BlackBoxCore.getContext().createPackageContext(
                info.packageName,
                Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY
        );
        Logger.d("Package context created successfully");

    } catch (Exception e) {
        Logger.e("createPackageContext failed: " + e.getMessage());

        try {
            Logger.d("Trying alternative package context creation...");
            packageContext = BlackBoxCore.getContext().createPackageContext(
                    info.packageName,
                    Context.CONTEXT_INCLUDE_CODE
            );
            Logger.d("Alternative package context created successfully");

        } catch (Exception e2) {
            Logger.e("Alternative createPackageContext also failed: " + e2.getMessage());
        }
    }

    return packageContext;
}

    // 安全地获取LoadedApk对象
    private Object getLoadedApkSafely(Context packageContext, ApplicationInfo applicationInfo) {
        Object loadedApk = null;

        if (packageContext != null) {
            try {
                Logger.d("Getting LoadedApk from package context...");
                loadedApk = ContextImpl.mPackageInfo.get(packageContext);
                Logger.d("LoadedApk obtained from context: " + (loadedApk != null ? "SUCCESS" : "NULL"));

            } catch (Exception e) {
                Logger.e("Failed to get LoadedApk from context: " + e.getMessage());
            }
        }

        // 如果从context获取失败，尝试通过ActivityThread直接创建
        if (loadedApk == null) {
            try {
                Logger.d("Attempting to create LoadedApk via ActivityThread...");
                loadedApk = createLoadedApkViaActivityThread(applicationInfo);
                Logger.d("ActivityThread LoadedApk creation: " + (loadedApk != null ? "SUCCESS" : "FAILED"));

            } catch (Exception e) {
                Logger.e("Failed to create LoadedApk via ActivityThread: " + e.getMessage());
            }
        }

        return loadedApk;
    }

    // 通过ActivityThread创建LoadedApk对象
    private Object createLoadedApkViaActivityThread(ApplicationInfo applicationInfo) {
        try {
            Object mainThread = BlackBoxCore.mainThread();
            if (mainThread == null) {
                Logger.e("MainThread is null, cannot create LoadedApk");
                return null;
            }

            // 使用原生Java反射，不依赖可能不存在的reflection包装方法
            Class<?> activityThreadClass = mainThread.getClass();
            Logger.d("ActivityThread class: " + activityThreadClass.getName());

            // 尝试多个可能的方法名
            String[] possibleMethods = {
                    "getPackageInfoNoCheck",
                    "peekPackageInfo",
                    "getPackageInfo"
            };

            // 先尝试带CompatibilityInfo参数的版本
            for (String methodName : possibleMethods) {
                try {
                    Method method = activityThreadClass.getDeclaredMethod(
                            methodName,
                            ApplicationInfo.class,
                            Class.forName("android.content.res.CompatibilityInfo.class")
                    );
                    method.setAccessible(true);
                    Object result = method.invoke(mainThread, applicationInfo, null);
                    if (result != null) {
                        Logger.d("Successfully created LoadedApk via method: " + methodName + "(ApplicationInfo, CompatibilityInfo)");
                        return result;
                    }
                } catch (NoSuchMethodException e) {
                    // 继续尝试下一个方法
                } catch (Exception e) {
                    Logger.w("Method " + methodName + " with CompatibilityInfo failed: " + e.getMessage());
                }
            }

            // 再尝试只有ApplicationInfo参数的版本
            for (String methodName : possibleMethods) {
                try {
                    Method method = activityThreadClass.getDeclaredMethod(methodName, ApplicationInfo.class);
                    method.setAccessible(true);
                    Object result = method.invoke(mainThread, applicationInfo);
                    if (result != null) {
                        Logger.d("Successfully created LoadedApk via method: " + methodName + "(ApplicationInfo)");
                        return result;
                    }
                } catch (NoSuchMethodException e) {
                    // 继续尝试下一个方法
                } catch (Exception e) {
                    Logger.w("Method " + methodName + " with ApplicationInfo only failed: " + e.getMessage());
                }
            }

            Logger.w("All LoadedApk creation methods failed");

        } catch (Exception e) {
            Logger.e("Native reflection LoadedApk creation failed: " + e.getMessage());
        }

        return null;
    }

    // 安全地获取ClassLoader
    private ClassLoader getClassLoaderSafely(Object loadedApk, String packageName) {
        ClassLoader classLoader = null;

        // 方法1: 从LoadedApk获取
        if (loadedApk != null) {
            try {
                Logger.d("Getting ClassLoader from LoadedApk...");
                classLoader = LoadedApk.getClassloader.call(loadedApk);
                Logger.d("ClassLoader from LoadedApk: " + (classLoader != null ? classLoader.getClass().getName() : "NULL"));

            } catch (Exception e) {
                Logger.e("Failed to get ClassLoader from LoadedApk: " + e.getMessage());
            }
        }

        // 方法2: 获取系统ClassLoader
        if (classLoader == null) {
            try {
                Logger.d("Attempting to get system ClassLoader...");
                classLoader = ClassLoader.getSystemClassLoader();
                Logger.d("System ClassLoader: " + (classLoader != null ? classLoader.getClass().getName() : "NULL"));

            } catch (Exception e) {
                Logger.e("System ClassLoader method failed: " + e.getMessage());
            }
        }

        // 方法3: 从Context获取ClassLoader
        if (classLoader == null) {
            try {
                Logger.d("Using context ClassLoader as fallback...");
                classLoader = BlackBoxCore.getContext().getClassLoader();
                Logger.d("Context ClassLoader: " + (classLoader != null ? classLoader.getClass().getName() : "NULL"));

            } catch (Exception e) {
                Logger.e("Context ClassLoader method failed: " + e.getMessage());
            }
        }

        // 方法4: 尝试通过包名创建Context获取ClassLoader
        if (classLoader == null && packageName != null) {
            try {
                Logger.d("Attempting to get ClassLoader via package context...");
                Context pkgContext = BlackBoxCore.getContext().createPackageContext(packageName, Context.CONTEXT_INCLUDE_CODE);
                if (pkgContext != null) {
                    classLoader = pkgContext.getClassLoader();
                    Logger.d("Package context ClassLoader: " + (classLoader != null ? classLoader.getClass().getName() : "NULL"));
                }

            } catch (Exception e) {
                Logger.e("Package context ClassLoader method failed: " + e.getMessage());
            }
        }

        return classLoader;
    }

    // bindApplication的入口方法
    public void bindApplication(final String packageName, final String processName) {
        if (mAppConfig == null) {
            return;
        }
        if (Looper.myLooper() != Looper.getMainLooper()) {
            final ConditionVariable conditionVariable = new ConditionVariable();
            new Handler(Looper.getMainLooper()).post(() -> {
                handleBindApplication(packageName, processName);
                conditionVariable.open();
            });
            conditionVariable.block();
        } else {
            handleBindApplication(packageName, processName);
        }
    }

    // 核心的应用绑定处理方法
    private synchronized void handleBindApplication(String packageName, String processName) {
        Logger.d("handleBindApplication - packageName=" + packageName + " processName=" + processName);

        // 首先设置环境伪装
        setupFakeEnvironmentWithReflection();

        DumpResult result = new DumpResult();
        result.packageName = packageName;
        result.dir = new File(BlackBoxCore.get().getDexDumpDir(), packageName).getAbsolutePath();

        try {
            // Step 1: 获取包信息
            PackageInfo packageInfo = BlackBoxCore.getBPackageManager().getPackageInfo(
                    packageName,
                    PackageManager.GET_PROVIDERS,
                    BActivityThread.getUserId()
            );
            if (packageInfo == null) {
                Logger.e("PackageInfo is null for: " + packageName);
                BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("PackageInfo is null"));
                return;
            }

            ApplicationInfo applicationInfo = packageInfo.applicationInfo;
            if (applicationInfo == null) {
                Logger.e("ApplicationInfo is null for: " + packageName);
                BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("ApplicationInfo is null"));
                return;
            }

            // 处理providers
            if (packageInfo.providers == null) {
                packageInfo.providers = new ProviderInfo[]{};
            }
            mProviders.addAll(Arrays.asList(packageInfo.providers));
            Logger.d("Step 1 - Package info loaded, providers count: " + mProviders.size());

            // Step 2: 获取ActivityThread的boundApplication
            Object boundApplication = null;
            try {
                boundApplication = ActivityThread.mBoundApplication.get(BlackBoxCore.mainThread());
                Logger.d("Step 2 - BoundApplication obtained: " + (boundApplication != null));
            } catch (Exception e) {
                Logger.w("Failed to get boundApplication: " + e.getMessage());
            }

            // Step 3: 创建PackageContext
            Context packageContext = createPackageContextSafely(applicationInfo);
            Logger.d("Step 3 - Package context: " + (packageContext != null ? "SUCCESS" : "FAILED"));

            // Step 4: 获取LoadedApk
            Object loadedApk = getLoadedApkSafely(packageContext, applicationInfo);
            Logger.d("Step 4 - LoadedApk: " + (loadedApk != null ? "SUCCESS" : "FAILED"));

            // 配置LoadedApk
            if (loadedApk != null) {
                try {
                    LoadedApk.mSecurityViolation.set(loadedApk, false);
                    LoadedApk.mApplicationInfo.set(loadedApk, applicationInfo);
                    Logger.d("LoadedApk configured successfully");
                } catch (Exception e) {
                    Logger.e("Failed to configure LoadedApk: " + e.getMessage());
                }
            }

            // Step 5: 清理dump目录
            FileUtils.deleteDir(new File(BlackBoxCore.get().getDexDumpDir(), packageName));

            // Step 6: 初始化VMCore
            VMCore.init(Build.VERSION.SDK_INT);
            if (packageContext != null) {
                IOCore.get().enableRedirect(packageContext);
            }
            Logger.d("Step 6 - VMCore initialized");

            // Step 7: 准备AppBindData
            AppBindData bindData = new AppBindData();
            bindData.appInfo = applicationInfo;
            bindData.processName = processName;
            bindData.info = loadedApk;
            bindData.providers = mProviders;

            // 配置boundApplication
            if (boundApplication != null && loadedApk != null) {
                try {
                    ActivityThread.AppBindData.instrumentationName.set(boundApplication,
                            new ComponentName(bindData.appInfo.packageName, Instrumentation.class.getName()));
                    ActivityThread.AppBindData.appInfo.set(boundApplication, bindData.appInfo);
                    ActivityThread.AppBindData.info.set(boundApplication, bindData.info);
                    ActivityThread.AppBindData.processName.set(boundApplication, bindData.processName);
                    ActivityThread.AppBindData.providers.set(boundApplication, bindData.providers);
                    Logger.d("BoundApplication configured successfully");
                } catch (Exception e) {
                    Logger.e("Failed to configure BoundApplication: " + e.getMessage());
                }
            }

            mBoundApplication = bindData;
            Logger.d("Step 7 - Bind data prepared");

            // Step 8: 获取ClassLoader
            ClassLoader classLoader = getClassLoaderSafely(loadedApk, packageName);
            if (classLoader == null) {
                Logger.e("Failed to obtain ClassLoader, cannot proceed with dump");
                BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("Failed to obtain ClassLoader"));
                return;
            }
            Logger.d("Step 8 - ClassLoader obtained: " + classLoader.getClass().getName());

            // Step 9: 创建Application
            Application application = null;
            try {
                BlackBoxCore.get().getAppLifecycleCallback().beforeCreateApplication(packageName, processName, packageContext);
                Logger.d("Step 9.1 - Before create application callback executed");

                if (loadedApk != null) {
                    try {
                        Logger.d("Step 9.2 - Attempting to create application via LoadedApk");
                        application = LoadedApk.makeApplication.call(loadedApk, false, null);
                        Logger.d("Step 9.3 - Application created successfully: " + (application != null ? application.getClass().getName() : "null"));

                    } catch (Throwable e) {
                        Logger.w("Application creation failed: " + e.getMessage());
                        Logger.w("Continuing without Application object...");
                    }
                }

                mInitialApplication = application;
                if (application != null) {
                    try {
                        ActivityThread.mInitialApplication.set(BlackBoxCore.mainThread(), mInitialApplication);
                        Logger.d("Initial application set in ActivityThread");
                    } catch (Exception e) {
                        Logger.w("Failed to set initial application: " + e.getMessage());
                    }
                }
                Logger.d("Step 9 - Application setup completed");

            } catch (Exception e) {
                Logger.e("Application creation process failed: " + e.getMessage());
                // 继续执行dump，即使没有Application对象
            }

            // Step 10: 开始Dump流程
            if (Objects.equals(packageName, processName)) {
                ClassLoader finalLoader = application != null ? application.getClassLoader() : classLoader;
                Logger.d("Step 10 - Starting dump with ClassLoader: " + finalLoader.getClass().getName());
                handleDumpDex(packageName, result, finalLoader);
            } else {
                Logger.d("Package name != process name, skipping dump");
                mAppConfig = null;
            }

        } catch (Throwable e) {
            Logger.e("handleBindApplication failed: " + e.getMessage());
            e.printStackTrace();
            mAppConfig = null;
            BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("handleBindApplication failed: " + e.getMessage()));
            BlackBoxCore.get().uninstallPackage(packageName);
        }
    }

    // 处理Dex dump的方法
    private void handleDumpDex(String packageName, DumpResult result, ClassLoader classLoader) {
        new Thread(() -> {
            Logger.d("Starting dump thread for package: " + packageName);
            try {
                // 给应用更多时间初始化
                Thread.sleep(2000);
                Logger.d("Dump thread initialization sleep completed");
            } catch (InterruptedException ignored) {
                Logger.w("Dump thread sleep interrupted");
            }

            try {
                Logger.d("=== 核心调用 VMCore.cookieDumpDex ===");
                Logger.d("ClassLoader: " + classLoader.getClass().getName());
                Logger.d("Package: " + packageName);

                // 这里是真正的dump核心调用
                VMCore.cookieDumpDex(classLoader, packageName);
                Logger.d("VMCore.cookieDumpDex completed successfully");

            } catch (Exception e) {
                Logger.e("VMCore.cookieDumpDex failed: " + e.getMessage());
                e.printStackTrace();
                BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("VMCore dump failed: " + e.getMessage()));

            } finally {
                // 清理和检查结果
                mAppConfig = null;
                checkDumpResult(result);
                BlackBoxCore.get().uninstallPackage(packageName);
            }
        }, "DumpThread-" + packageName).start();
    }

    // 检查dump结果
    private void checkDumpResult(DumpResult result) {
        File dir = new File(result.dir);
        Logger.d("Checking dump result directory: " + dir.getAbsolutePath());

        if (!dir.exists()) {
            Logger.e("Dump directory does not exist");
            BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("dump directory not found"));
            return;
        }

        File[] files = dir.listFiles();
        if (files == null || files.length == 0) {
            Logger.e("No dex files found in dump directory");
            BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError("not found dex file"));
            return;
        }

        Logger.d("=== Dump Success ===");
        Logger.d("Found " + files.length + " files in dump directory:");
        long totalSize = 0;
        for (File file : files) {
            long fileSize = file.length();
            totalSize += fileSize;
            Logger.d("  - " + file.getName() + " (" + fileSize + " bytes)");
        }
        Logger.d("Total dump size: " + totalSize + " bytes");

        BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpSuccess());
    }

    // IBinder接口实现方法
    @Override
    public IBinder getActivityThread() {
        try {
            return ActivityThread.getApplicationThread.call(BlackBoxCore.mainThread());
        } catch (Exception e) {
            Logger.e("Failed to get activity thread: " + e.getMessage());
            return null;
        }
    }

    @Override
    public void bindApplication() {
        if (!isInit()) {
            String packageName = getAppPackageName();
            String processName = getAppProcessName();
            if (packageName != null && processName != null) {
                bindApplication(packageName, processName);
            } else {
                Logger.e("Cannot bind application: packageName or processName is null");
            }
        } else {
            Logger.d("Application already initialized, skipping bind");
        }
    }

    // 强制清理当前应用状态（调试用）
    public static void forceCleanup() {
        BActivityThread instance = currentActivityThread();
        synchronized (BActivityThread.class) {
            instance.mAppConfig = null;
            instance.mBoundApplication = null;
            instance.mInitialApplication = null;
            instance.mProviders.clear();
            Logger.d("BActivityThread state force cleaned");
        }
    }

    // 获取应用详细信息的调试方法
    public static String getDebugInfo() {
        StringBuilder sb = new StringBuilder();
        AppConfig config = getAppConfig();

        sb.append("=== BActivityThread Debug Info ===\n");
        sb.append("App Package: ").append(getAppPackageName()).append("\n");
        sb.append("Process Name: ").append(getAppProcessName()).append("\n");
        sb.append("App PID: ").append(getAppPid()).append("\n");
        sb.append("App UID: ").append(getAppUid()).append("\n");
        sb.append("User ID: ").append(getUserId()).append("\n");
        sb.append("Is Initialized: ").append(currentActivityThread().isInit()).append("\n");
        sb.append("Has Application: ").append(getApplication() != null).append("\n");
        sb.append("Providers Count: ").append(getProviders().size()).append("\n");

        sb.append("Environment Spoofed: ").append(sEnvironmentSpoofed).append("\n");
        sb.append("================================");

        return sb.toString();
    }

    // 应用绑定数据的内部类
    public static class AppBindData {
        public String processName;
        public ApplicationInfo appInfo;
        public List<ProviderInfo> providers;
        public Object info;  // LoadedApk对象

        @Override
        public String toString() {
            return "AppBindData{" +
                    "processName='" + processName + '\'' +
                    ", appInfo=" + (appInfo != null ? appInfo.packageName : "null") +
                    ", providers=" + (providers != null ? providers.size() : 0) +
                    ", info=" + (info != null ? info.getClass().getSimpleName() : "null") +
                    '}';
        }
    }

    // 生命周期回调接口
    public interface AppLifecycleCallback {
        void onAppCreate(String packageName, String processName);
        void onAppDestroy(String packageName, String processName);
        void beforeCreateApplication(String packageName, String processName, Context context);
        void afterCreateApplication(String packageName, String processName, Application application);
    }

    // 默认的生命周期回调实现
    public static class DefaultAppLifecycleCallback implements AppLifecycleCallback {
        @Override
        public void onAppCreate(String packageName, String processName) {
            Logger.d("App created: " + packageName + " (" + processName + ")");
        }

        @Override
        public void onAppDestroy(String packageName, String processName) {
            Logger.d("App destroyed: " + packageName + " (" + processName + ")");
        }

        @Override
        public void beforeCreateApplication(String packageName, String processName, Context context) {
            Logger.d("Before create application: " + packageName + " (" + processName + ")");
        }

        @Override
        public void afterCreateApplication(String packageName, String processName, Application application) {
            Logger.d("After create application: " + packageName + " (" + processName + ")");
        }
    }

    // 异常处理的辅助方法
    private void handleException(String operation, Exception e, DumpResult result) {
        Logger.e(operation + " failed: " + e.getMessage());
        e.printStackTrace();

        if (result != null) {
            BlackBoxCore.getBDumpManager().noticeMonitor(result.dumpError(operation + " failed: " + e.getMessage()));
        }

        // 清理状态
        mAppConfig = null;

        // 如果有包名，卸载包
        String packageName = getAppPackageName();
        if (packageName != null) {
            BlackBoxCore.get().uninstallPackage(packageName);
        }
    }

    // 验证核心组件是否可用
    private boolean validateCoreComponents() {
        try {
            if (BlackBoxCore.mainThread() == null) {
                Logger.e("MainThread is null");
                return false;
            }

            if (BlackBoxCore.getContext() == null) {
                Logger.e("BlackBox context is null");
                return false;
            }

            if (BlackBoxCore.getBPackageManager() == null) {
                Logger.e("BPackageManager is null");
                return false;
            }

            if (BlackBoxCore.getBDumpManager() == null) {
                Logger.e("BDumpManager is null");
                return false;
            }

            return true;

        } catch (Exception e) {
            Logger.e("Core components validation failed: " + e.getMessage());
            return false;
        }
    }

    // 重置环境伪装状态（测试用）
    public static void resetEnvironmentSpoof() {
        sEnvironmentSpoofed = false;
        Logger.d("Environment spoof state reset");
    }

    // 获取当前线程信息
    public static String getCurrentThreadInfo() {
        Thread currentThread = Thread.currentThread();
        return "Thread: " + currentThread.getName() +
                " (ID: " + currentThread.getId() +
                ", Priority: " + currentThread.getPriority() +
                ", Group: " + (currentThread.getThreadGroup() != null ? currentThread.getThreadGroup().getName() : "null") + ")";
    }

    // toString方法，便于调试
    @Override
    public String toString() {
        return "BActivityThread{" +
                "mAppConfig=" + (mAppConfig != null ? mAppConfig.packageName : "null") +
                ", mBoundApplication=" + (mBoundApplication != null) +
                ", mInitialApplication=" + (mInitialApplication != null ? mInitialApplication.getClass().getSimpleName() : "null") +
                ", mProviders=" + mProviders.size() +
                ", sEnvironmentSpoofed=" + sEnvironmentSpoofed +
                '}';
    }

    // 析构方法，确保资源清理
    @Override
    protected void finalize() throws Throwable {
        try {
            Logger.d("BActivityThread finalize called");
            forceCleanup();
        } finally {
            super.finalize();
        }
    }
}