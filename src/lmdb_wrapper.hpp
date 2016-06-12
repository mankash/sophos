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
        
        
        void get() const;
        void put();
        
        
        inline static std::string error_string(const int errc)
        {
            return std::string(mdb_strerror(errc));
        }
        
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
        Transaction(LMDBWrapper *w,MDB_txn *txn);
        ~Transaction();
        
        void close();
        void abort();
    private:
        LMDBWrapper *wrapper_;
        MDB_txn *txn_;
    };
}
}