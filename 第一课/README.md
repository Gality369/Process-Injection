# 使用
两种手法都已经封装成函数, 在需要获取SeDebug权限时，直接将代码复制进项目，然后按照类似如下格式去调用即可

```c++
 if (EnableDebugPrivilege() == FALSE) {
        printf("failed to get SeDebug Privilege");
        return -1;
    }
```

还是不知道怎么用的话，请参考第二节课中的用法