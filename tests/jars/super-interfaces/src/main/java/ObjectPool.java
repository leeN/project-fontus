import internal.BaseGenericObjectPool;
import internal.*;

import java.util.Collection;

public class ObjectPool<T> extends BaseGenericObjectPool<T>  implements internal.ObjectPool<T>, ObjectPoolMXBean<T>  {
    public void addAll(Collection<T> collection) {
        for(T item : collection) {
            this.addObject(item);
        }
    }
}
