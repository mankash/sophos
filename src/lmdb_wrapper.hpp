//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#pragma once

#include "logger.hpp"

#include <lmdb.h>      /* for MDB_*, mdb_*() */


#ifdef LMDBXX_DEBUG
#include <cassert>     /* for assert() */
#endif
#include <cstddef>     /* for std::size_t */
#include <cstdio>      /* for std::snprintf() */
#include <cstring>     /* for std::strlen() */
#include <stdexcept>   /* for std::runtime_error */
#include <string>      /* for std::string */
#include <type_traits> /* for std::is_pod<> */

namespace sse {
namespace sophos {


    class LMDBWrapper
    {
    public:
        LMDBWrapper(const std::string& db_path, const size_t setup_size, const size_t key_size, const size_t data_size);
        LMDBWrapper(const std::string& db_path);
        ~LMDBWrapper();
        
        class Transaction;
        
        Transaction ro_transaction() const;
        Transaction rw_transaction();
        
        inline MDB_dbi dbi() const;
        
        bool resize();
        
        inline bool put(const MDB_val& key, const MDB_val& val);

        template<typename K, typename V>
            inline bool put(const K& key, const V& val);
        
        
        inline static std::string error_string(const int errc);
        
    private:
        bool write_metadata(const std::string& md_path) const;
        
        ::MDB_env *env_;
        ::MDB_dbi dbi_;
        
        size_t current_edb_size_;
        static constexpr float edb_size_increase_step__ = 0.2;
        
        static constexpr int lmdb_env_flags__ = MDB_WRITEMAP | MDB_NORDAHEAD;
        static constexpr mode_t lmdb_file_mode__ = 0644;
        
        static const std::string data_dir;
        static const std::string md_file;

    };
    
    class LMDBWrapper::Transaction
    {
    public:
        inline Transaction(const LMDBWrapper* w, MDB_txn *txn);
        inline ~Transaction();
        
        inline void commit();
        inline void abort();
        
        template<typename V>
            inline bool get(const MDB_val& key, V& val) const;
        
        template<typename K, typename V>
            inline bool get(const K& key, V& val) const;

        template<typename V>
            inline bool get(const std::string& key, V& val) const;
        
    private:
        const LMDBWrapper* wrapper_;
        MDB_txn *txn_;
    };
    
    std::string LMDBWrapper::error_string(const int errc)
    {
        return std::string(mdb_strerror(errc));
    }
    
    MDB_dbi LMDBWrapper::dbi() const
    {
        return dbi_;
    }
    
    LMDBWrapper::Transaction LMDBWrapper::ro_transaction() const
    {
        MDB_txn *txn;
        int errc = mdb_txn_begin(env_, NULL, MDB_RDONLY, &txn);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to begin transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            
            return LMDBWrapper::Transaction(this, NULL);
        }

        return LMDBWrapper::Transaction(this, txn);
    }
    
    LMDBWrapper::Transaction LMDBWrapper::rw_transaction()
    {
        MDB_txn *txn;
        int errc = mdb_txn_begin(env_, NULL, 0, &txn);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to begin transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            
            return LMDBWrapper::Transaction(this, NULL);
        }
        
        return LMDBWrapper::Transaction(this, txn);
    }
    
    template<typename K, typename V>
    inline bool LMDBWrapper::put(const K& key, const V& val)
    {
        MDB_val k{sizeof(K), const_cast<void*>(&key)};
        MDB_val v{sizeof(V), const_cast<void*>(&val)};
        
        return put(k, v);
    }

    
    LMDBWrapper::Transaction::Transaction(const LMDBWrapper* w, MDB_txn *txn)
    : wrapper_(w), txn_(txn)
    {
    }
    
    LMDBWrapper::Transaction::~Transaction()
    {
        if (txn_) {
            mdb_txn_commit(txn_);
            txn_ = NULL;
        }
    }
    
    void LMDBWrapper::Transaction::commit()
    {
        if (txn_) {
            mdb_txn_commit(txn_);
            txn_ = NULL;
        }
    }
    
    void LMDBWrapper::Transaction::abort()
    {
        if (txn_) {
            mdb_txn_abort(txn_);
            txn_ = NULL;
        }
    }

    template<typename V>
    bool LMDBWrapper::Transaction::get(const MDB_val& key,
                                       V& val) const {
        if (txn_ == NULL) {
            logger::log(logger::ERROR) << "Invalid transaction" << std::endl;
            return false;
        }
        
        MDB_val v{};
        const bool result = mdb_get(txn_, wrapper_->dbi(), const_cast<MDB_val*>(&key), &v);
        if (result) {
            val = *reinterpret_cast<const V*>(v.mv_data);
        }
        return result;
    }
    
    template<typename K, typename V>
    bool LMDBWrapper::Transaction::get(const K& key,
                                       V& val) const {
        MDB_val k{sizeof(K), const_cast<void*>(&key)};
        return get(k, val);
    }
    
    template<typename V>
    bool LMDBWrapper::Transaction::get(const std::string& key,
                                       V& val) const {
        MDB_val k{key.length(), const_cast<void*>(reinterpret_cast<const void*>(key.c_str()))};
        return get(k, val);
    }
}
}