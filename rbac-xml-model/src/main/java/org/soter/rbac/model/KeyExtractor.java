/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.soter.rbac.model;

/**
 * Extracts an immutable key for this object.
 *
 * It is important for the key to not be mutable and that the key value
 * itself is not changed in the object.  If this happens any AutoIndex,
 * or Map using this key will break.
 */
public interface KeyExtractor<K,V> {
    /**
     * Gets the immutable key for the specified value.
     * @return gets the immutable key for the specified value
     */
    K getKey(V value);
}
