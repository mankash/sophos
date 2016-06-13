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

#ifndef __LMDB_WRAPPER__
#define __LMDB_WRAPPER__

#include "logger.hpp"
#include "utils.hpp"

#include "lmdb++.h"

#include <iostream>

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
        
        class Transaction;
        
        inline const lmdb::env& env() const;
        inline lmdb::dbi& dbi();
        inline const lmdb::dbi& dbi() const;

        inline size_t entries() const;
        
        bool resize();
        
        template<typename K, typename V>
        inline bool put(const K& key, const V& data);
        
        inline static std::string error_string(const int errc);
        
    private:
        bool write_metadata(const std::string& md_path) const;
        
        lmdb::env env_;
        lmdb::dbi dbi_;
        
        std::string db_path_;
        
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
        inline Transaction(const LMDBWrapper& w, bool ro);
        inline ~Transaction();
        
        inline void commit();
        inline void abort();
        
        template<typename K, typename V>
            inline bool get(const K& key, V& data) const;

    private:
        const LMDBWrapper* wrapper_;
        lmdb::txn txn_;
    };
    
    std::string LMDBWrapper::error_string(const int errc)
    {
        return std::string(mdb_strerror(errc));
    }
    
    inline const lmdb::env& LMDBWrapper::env() const
    {
        return env_;
    }
    
    lmdb::dbi& LMDBWrapper::dbi()
    {
        return dbi_;
    }
    
    const lmdb::dbi& LMDBWrapper::dbi() const
    {
        return dbi_;
    }
    
    template<typename K, typename V>
    inline bool LMDBWrapper::put(const K& key, const V& data)
    {
        // create a new transaction
        lmdb::txn txn = lmdb::txn::begin(env().handle(), NULL, 0);
        
        int errc = 0;
        
        try {
            dbi_.put(txn.handle(), key, data, 0, &errc);

            txn.commit();
            
        } catch (std::exception &e) {
            if (errc == MDB_MAP_FULL) {
                // abort the transaction
                txn.abort();

                // resize
                resize();
                
                // re-run the transaction
                txn = lmdb::txn::begin(env().handle(), NULL, 0);
                
                dbi_.put(txn.handle(), key, data, 0 , &errc);

            }else if(errc != MDB_SUCCESS){
                logger::log(logger::ERROR) << "Error during database put: " << error_string(errc) << std::endl;
            }
            
            
        }
        
        return (errc == MDB_SUCCESS);
    }

    inline size_t LMDBWrapper::entries() const
    {
        MDB_txn *txn;
        int errc = mdb_txn_begin(env_, NULL, MDB_RDONLY, &txn);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to begin transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            
            return 0;
        }

        MDB_stat stat;
        mdb_stat(txn, dbi(), &stat);
        mdb_txn_commit(txn);
        
        return stat.ms_entries;
    }

    LMDBWrapper::Transaction::Transaction(const LMDBWrapper& w, bool ro)
    : wrapper_(&w), txn_(lmdb::txn::begin(w.env().handle(), NULL, (ro ? MDB_RDONLY : 0)))
    {
    }
    
    LMDBWrapper::Transaction::~Transaction()
    {
    }
    
    void LMDBWrapper::Transaction::commit()
    {
        txn_.commit();
    }
    
    void LMDBWrapper::Transaction::abort()
    {
        txn_.abort();
    }
    
    template<typename K, typename V>
    bool LMDBWrapper::Transaction::get(const K& key,
                                       V& data) const {
        return wrapper_->dbi().get(txn_.handle(), key, data);
    }

}
}

#endif