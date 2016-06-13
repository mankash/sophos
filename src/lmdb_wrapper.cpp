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


#include "lmdb_wrapper.hpp"

#include "logger.hpp"
#include "utils.hpp"

#include <iostream>
#include <fstream>
#include <algorithm>

namespace sse {
namespace sophos {

    const std::string LMDBWrapper::data_dir = "data";
    const std::string LMDBWrapper::md_file = "info.bin";

    static void init_lmdb_struct(const std::string& db_path, const int env_flags, const mode_t mode, const bool create, lmdb::env &env, lmdb::dbi &dbi)
    {
        
        env.open(db_path.c_str(), env_flags, mode);
        
        lmdb::txn txn = lmdb::txn::begin(env.handle(), NULL, 0);
        
        if (create) {
            dbi = lmdb::dbi::open(txn.handle(), NULL, MDB_CREATE);
        }else{
            dbi = lmdb::dbi::open(txn.handle(), NULL, 0);
        }
        txn.commit();
    }
    
    LMDBWrapper::LMDBWrapper(const std::string& db_path, const size_t setup_size, const size_t key_size, const size_t data_size) :
        env_(lmdb::env::create()), dbi_(NULL), db_path_(db_path)
    {
        if (!is_directory(db_path)) {
            throw std::runtime_error(db_path + ": not a directory");
        }
        
        std::string lmdb_data_path = db_path + "/" + data_dir;
        
        if (exists(lmdb_data_path)) {
            throw std::runtime_error("File or directory already exists at " + lmdb_data_path);
        }else{
            if (!create_directory(lmdb_data_path, (mode_t)0700)) {
                throw std::runtime_error(lmdb_data_path + ": unable to create directory");
            }

            
            // set to the right size
            current_edb_size_ = setup_size * (key_size + data_size);
//            current_edb_size_ = std::max<size_t>(current_edb_size_, 1024*1024);
            
            env_.set_mapsize(current_edb_size_);

            
            std::string md_path = db_path + "/" + md_file;
            
            if (!write_metadata(md_path)) {
                logger::log(logger::CRITICAL) << "Unable to write the database metadata." << std::endl;
                exit(-1);
            }
            
            init_lmdb_struct(lmdb_data_path, lmdb_env_flags__, lmdb_file_mode__, true, env_, dbi_);

        }
        
    }
    
    LMDBWrapper::LMDBWrapper(const std::string& db_path) :
    env_(lmdb::env::create()), dbi_(NULL), db_path_(db_path)
    {
        if (!is_directory(db_path)) {
            throw std::runtime_error(db_path + ": not a directory");
        }
        
        std::string lmdb_data_path = db_path + "/" + data_dir;

        
        // read the meta data
        std::string md_path = db_path + "/" + md_file;

        if (!is_file(md_path)) {
            // error, the metadata file is not there
            throw std::runtime_error("Missing metadata file");
        }
        std::ifstream md_in(md_path.c_str());
        md_in >> current_edb_size_;
        
        // set to the right size
        env_.set_mapsize(current_edb_size_);
        
        init_lmdb_struct(lmdb_data_path, lmdb_env_flags__, lmdb_file_mode__, true, env_, dbi_);

    }
    

    bool LMDBWrapper::write_metadata(const std::string& md_path) const
    {
        std::ofstream md_out(md_path.c_str());
        if (!md_out.is_open()) {
            throw std::runtime_error(md_path + ": unable to write the metadata");
        }
        
        md_out << current_edb_size_ << std::endl;
        md_out.close();
        
        return true;
    }

    bool LMDBWrapper::resize()
    {
        // we need to resize the DB's map
        logger::log(logger::INFO) << "Resizing the database" << std::endl;
        
        current_edb_size_ *= (1+edb_size_increase_step__);
        // set the new size

        env_.set_mapsize(current_edb_size_);
        
        std::string md_path = db_path_ + "/" + md_file;
        return write_metadata(md_path);
        
        return true;
    }


}
}