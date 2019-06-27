/*
 * Copyright (c) 2018 Jämes Ménétrey <james@menetrey.me>
 *
 * This file is part of the Keystone Java bindings which is released under MIT.
 * See file LICENSE in the Java bindings folder for full license details.
 */

package keystone.jna;

import com.sun.jna.DefaultTypeMapper;
import com.sun.jna.FromNativeContext;
import com.sun.jna.ToNativeContext;
import com.sun.jna.TypeConverter;

import java.util.function.Function;

/**
 * Extends the default type mapper of JNA in order to provide custom bindings for enumerations.
 */
class EnumTypeMapper extends DefaultTypeMapper {
    /**
     * Add a {@link TypeConverter} to provide bidirectional mapping between
     * a native and Java type.
     *
     * @param enumerationType   The type of the enumeration to bind.
     * @param fromNativeInteger A function that converts the native enumeration into the Java enumeration.
     * @param <T>               The type of the Java enumeration.
     */
    <T extends JnaEnum> void addTypeConverter(Class<T> enumerationType, Function<Integer, T> fromNativeInteger) {
        addTypeConverter(enumerationType, new TypeConverter() {

            /**
             * Converts the native enumeration into the Java enumeration.
             *
             * @param nativeValue The native element.
             * @param context The context for converting a native value into a Java type.
             * @return The return value is a Java enumeration.
             */
            @Override
            public Object fromNative(Object nativeValue, FromNativeContext context) {
                return fromNativeInteger.apply((int) nativeValue);
            }

            /**
             * Returns the native type of the conversion. The enumeration are of type {@link Integer}.
             */
            @Override
            public Class<?> nativeType() {
                return Integer.class;
            }

            /**
             * Converts a Java enumeration into a native enumeration.
             *
             * @param value The Java element.
             * @param context The context of converting a Java type into a native value.
             * @return The return value is a native value from an enumeration.
             */
            @Override
            public Object toNative(Object value, ToNativeContext context) {
                return ((JnaEnum) value).value();
            }
        });
    }
}
