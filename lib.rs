#![cfg_attr(not(feature = "std"), no_std)]
use ink_lang as ink;

#[ink::contract]
mod peer_name_service {

    use ink_prelude::vec::Vec;

    use ink_storage::collections::HashMap;

    use ink_env::hash::{Blake2x128, HashOutput};
    //use ink_storage:: collections:: Vec;
    use scale::{Decode, Encode};

    // Resolver is the resolved pns value
    // It could be a wallet, contract, IPFS content hash, IPv4, IPv6 etc
    pub type Resolver = AccountId;

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NotOwner,
        NotApproved,
        TokenExists,
        TokenNotFound,
        CannotInsert,
        CannotRemove,
        CannotFetchValue,
        NotAllowed,
        UnauthorizedCaller,
        /// Returned if the name already exists upon registration.
        NameAlreadyExists,
        /// Returned if the name not exists upon registration.
        NameNotExists,
        /// Returned if caller is not owner while required to.
        CallerIsNotOwner,
    }

    #[ink(event)]
    pub struct NewOwner {
        #[ink(topic)]
        node: [u8; 16],
        #[ink(topic)]
        owner: AccountId,
    }

    #[ink(event)]
    pub struct SubNode {
        #[ink(topic)]
        owner: AccountId,
        #[ink(topic)]
        node: [u8; 16],
        #[ink(topic)]
        subnode: [u8; 16],
    }

    #[ink(event)]
    pub struct NewResolver {
        #[ink(topic)]
        node: [u8; 16],
        #[ink(topic)]
        resolver: Resolver,
    }

    #[ink(event)]
    pub struct Transfer {
        #[ink(topic)]
        node: [u8; 16],
        #[ink(topic)]
        owner: AccountId,
    }

    /// Event emitted when admin change manager.
    #[ink(event)]
    pub struct ChangeManager {
        #[ink(topic)]
        _current_manager: Option<AccountId>,
        #[ink(topic)]
        _new_manager: Option<AccountId>,
    }

    /// Emitted whenever a new name is being registered.
    #[ink(event)]
    pub struct Register {
        #[ink(topic)]
        node: [u8; 16],
        #[ink(topic)]
        from: AccountId,
    }

    /// Emitted whenever an address changes.
    #[ink(event)]
    pub struct SetAddress {
        #[ink(topic)]
        name: [u8; 16],
        from: AccountId,
        #[ink(topic)]
        old_address: Option<AccountId>,
        #[ink(topic)]
        new_address: AccountId,
    }

    #[ink(storage)]
    #[derive(Default)]
    pub struct PeerName {
        records: HashMap<[u8; 16], AccountId>, // mapping of domain name to owner
        resolvers: HashMap<[u8; 16], Resolver>, // mapping of domain name to resolver

        /// stores admin id of contract
        admin: AccountId,

        /// Stores current manager account id of contract
        manager: AccountId,
    }

    impl PeerName {
        #[ink(constructor)]
        pub fn default(_admin: AccountId, _manager: AccountId) -> Self {
            Self {
                records: Default::default(),
                resolvers: Default::default(),

                manager: _manager,
                admin: _admin,
            }
        }

        fn authorized(&self, node: &[u8; 16]) -> bool {
            let caller = Self::env().caller();

            let node_owner = self.records.get(node).cloned();

            if Some(caller) == node_owner {
                true
            } else {
                false
            }
        }

        /// Register specific name with caller as owner.
        #[ink(message)]
        pub fn register_domain(
            &mut self,
            domain: Vec<u8>,
            owner: AccountId,
            resolver: Resolver,
        ) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.manager {
                return Err(Error::UnauthorizedCaller);
            };
            let node = self.get_node(domain);
            if self.records.contains_key(&node) {
                return Err(Error::NameAlreadyExists);
            }

            self._set_owner(node, owner);
            self._set_resolver(node, resolver);
            self.env().emit_event(Register { node, from: owner });

            Ok(())
        }

        /// Register specific name with caller as owner.
        #[ink(message)]
        pub fn set_sub_domain(
            &mut self,
            domain: Vec<u8>,
            subdomain: Vec<u8>,
            resolver: Resolver,
        ) -> Result<(), Error> {
            let caller = self.env().caller();

            let node = self.get_node(domain.clone());
            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
            if !self.authorized(&node) {
                return Err(Error::UnauthorizedCaller);
            }
            let subnode = self.get_subnode(domain, subdomain);

            if self.records.contains_key(&subnode) {
                return Err(Error::NameAlreadyExists);
            }
            // self._set_record(subnode, caller, resolver);
            self._set_owner(subnode, caller);
            self._set_resolver(subnode, resolver);
            self.env().emit_event(Register {
                node: subnode,
                from: caller,
            });

            Ok(())
        }

        /// update node resolver
        #[ink(message)]
        pub fn update_domain_resolver(
            &mut self,
            domain: Vec<u8>,
            resolver: Resolver,
        ) -> Result<(), Error> {
            let node = self.get_node(domain);

            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
            if !self.authorized(&node) {
                return Err(Error::UnauthorizedCaller);
            }
            self._set_resolver(node, resolver);
            Ok(())
        }

        /// update node resolver
        #[ink(message)]
        pub fn update_subdomain_resolver(
            &mut self,
            domain: Vec<u8>,
            resolver: Resolver,
            subdomain: Vec<u8>,
        ) -> Result<(), Error> {
            let node = self.get_node(domain.clone());

            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
            if !self.authorized(&node) {
                return Err(Error::UnauthorizedCaller);
            }

            let subnode = self.get_subnode(domain, subdomain);
            self._set_resolver(subnode, resolver);
            Ok(())
        }

        /// owner of a node transfers ownership to a new account.
        #[ink(message)]
        pub fn transfer_domain_ownership(
            &mut self,
            domain: Vec<u8>,
            new_owner: AccountId,
        ) -> Result<(), Error> {
            let node = self.get_node(domain.clone());
            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
            if !self.authorized(&node) {
                return Err(Error::UnauthorizedCaller);
            }

            self._set_owner(node, new_owner);
            self.env().emit_event(Transfer {
                node,
                owner: new_owner,
            });

            Ok(())
        }

        /// Node exist or note
        #[ink(message)]
        pub fn is_domain_exist(&self, domain: Vec<u8>) -> bool {
            let node = self.get_node(domain);
            if self.records.contains_key(&node) {
                true
            } else {
                false
            }
        }

        /// renounce ownership by manager
        #[ink(message)]
        pub fn renounce_ownership(&mut self ,  domain: Vec<u8>) -> Result<(), Error> {
            let caller = self.env().caller();
            let  node = self.get_node(domain);
            if caller != self.manager {
                return Err(Error::UnauthorizedCaller);
            };       
            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
           self.records.take(&node);
           Ok(())
        }


        /// renounce ownership by oner only
        #[ink(message)]
        pub fn renounce_my_ownership(&mut self ,  domain: Vec<u8>) -> Result<(), Error> {
            let  node = self.get_node(domain);
            if !self.authorized(&node) {
                return Err(Error::UnauthorizedCaller);
            };       
            if !self.records.contains_key(&node) {
                return Err(Error::NameNotExists);
            }
           self.records.take(&node);
           Ok(())
        }

        /// SubNode exist or note
        #[ink(message)]
        pub fn is_subdomain_exist(&self, domain: Vec<u8>, subdomain: Vec<u8>) -> bool {
            let subnode = self.get_subnode(domain, subdomain);
            if self.records.contains_key(&subnode) {
                true
            } else {
                false
            }
        }

        fn _set_owner(&mut self, node: [u8; 16], owner: AccountId) -> bool {
            // let node = self.get_node(domain);
            self.records.insert(node, owner);
            self.env().emit_event(Transfer {
                node: node,
                owner: owner,
            });

            return true;
        }

        fn _set_resolver(&mut self, node: [u8; 16], resolver: Resolver) {
            // let node = self.get_node(domain);

            self.resolvers.insert(node, resolver);
            self.env().emit_event(NewResolver { node, resolver });
        }

        /// Current manager of contract
        #[ink(message)]
        pub fn current_manager(&self) -> AccountId {
            self.manager
        }

        /// Admin of the contract
        #[ink(message)]
        pub fn admin(&self) -> AccountId {
            self.admin
        }

        /// Only Admin can change the current manager
        #[ink(message)]
        pub fn change_manager(&mut self, _manager: AccountId) -> Result<(), Error> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::UnauthorizedCaller);
            };

            self.manager = _manager;

            self.env().emit_event(ChangeManager {
                _current_manager: Some(self.manager),
                _new_manager: Some(_manager),
            });

            Ok(())
        }

        /// calculate subnode from lable
        #[ink(message)]
        pub fn get_node(&self, domain: Vec<u8>) -> [u8; 16] {
            let encodable = domain; // Implements `scale::Encode`
            let mut output = <Blake2x128 as HashOutput>::Type::default(); // 256-bit buffer
            ink_env::hash_encoded::<Blake2x128, _>(&encodable, &mut output);
            output
        }

        /// calculate subnode from lable
        #[ink(message)]
        pub fn get_subnode(&self, domain: Vec<u8>, subdomain: Vec<u8>) -> [u8; 16] {
            let encodable = (domain, subdomain); // Implements `scale::Encode`
            let mut output = <Blake2x128 as HashOutput>::Type::default(); // 256-bit buffer
            ink_env::hash_encoded::<Blake2x128, _>(&encodable, &mut output);
            output
        }

        #[ink(message)]
        pub fn owner(&self, domain: Vec<u8>) -> Option<AccountId> {
            let node = self.get_node(domain);
            self.records.get(&node).cloned()
            //self.token_approvals.get(&id).cloned()
        }

        //    /// Returns the approved account ID for this token if any.
        //    #[ink(message)]
        //    pub fn get_approved(&self, id: TokenId) -> Option<AccountId> {
        //        self.token_approvals.get(&id).cloned()
        //    }

        #[ink(message)]
        pub fn domain_resolver(&self, domain: Vec<u8>) -> Option<Resolver> {
            let node = self.get_node(domain);
            return self.resolvers.get(&node).cloned();
        }
        #[ink(message)]
        pub fn subdomain_resolver(&self, domain: Vec<u8>, subdomain: Vec<u8>) -> Option<Resolver> {
            let node = self.get_subnode(domain, subdomain);
            return self.resolvers.get(&node).cloned();
        }
    }
}
