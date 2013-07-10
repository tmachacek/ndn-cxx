/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_PUBLISHERPUBLICKEYDIGEST_HPP
#define	NDN_PUBLISHERPUBLICKEYDIGEST_HPP

#include <vector>
#include "c/PublisherPublicKeyDigest.h"

namespace ndn {
  
/**
 * A PublisherPublicKeyDigest holds the publisher public key digest value, if any.
 * We make a separate class since this is used by multiple other classes.
 */
class PublisherPublicKeyDigest {
public:    
  PublisherPublicKeyDigest() {
  }
  
  /**
   * Set the publisherPublicKeyDigestStruct to point to the entries in this PublisherPublicKeyDigest, without copying any memory.
   * WARNING: The resulting pointers in publisherPublicKeyDigestStruct are invalid after a further use of this object which could reallocate memory.
   * @param publisherPublicKeyDigestStruct a C ndn_PublisherPublicKeyDigest struct to receive the pointer
   */
  void get(struct ndn_PublisherPublicKeyDigest &publisherPublicKeyDigestStruct) const 
  {
    publisherPublicKeyDigestStruct.publisherPublicKeyDigestLength = publisherPublicKeyDigest_.size();
    if (publisherPublicKeyDigest_.size() > 0)
      publisherPublicKeyDigestStruct.publisherPublicKeyDigest = (unsigned char *)&publisherPublicKeyDigest_[0];
    else
      publisherPublicKeyDigestStruct.publisherPublicKeyDigest = 0;
  }
  
  /**
   * Clear this PublisherPublicKeyDigest, and copy from the ndn_PublisherPublicKeyDigest struct.
   * @param excludeStruct a C ndn_Exclude struct
   */
  void set(struct ndn_PublisherPublicKeyDigest &publisherPublicKeyDigestStruct) 
  {
  	publisherPublicKeyDigest_.clear();
    if (publisherPublicKeyDigestStruct.publisherPublicKeyDigest)
      publisherPublicKeyDigest_.insert
        (publisherPublicKeyDigest_.begin(), publisherPublicKeyDigestStruct.publisherPublicKeyDigest, 
         publisherPublicKeyDigestStruct.publisherPublicKeyDigest + publisherPublicKeyDigestStruct.publisherPublicKeyDigestLength);
  }

  const std::vector<unsigned char> &getPublisherPublicKeyDigest() const { return publisherPublicKeyDigest_; }

private:
	std::vector<unsigned char> publisherPublicKeyDigest_;
};
  
}

#endif
