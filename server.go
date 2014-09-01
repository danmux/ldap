package ldap

//import "github.com/kr/pretty"

import (
	"crypto/tls"
	"errors"
	"github.com/vanackere/asn1-ber"
	"io"
	"log"
	"net"
	"strings"
)

type Binder interface {
	Bind(bindDN, bindSimplePw, clientIP string) uint64
}
type Searcher interface {
	Search(boundDN string, searchReq SearchRequest, clientIP string) ServerSearchResult
}

/////////////////////////
type Server struct {
	bindFns   map[string]Binder
	searchFns map[string]Searcher
	quit      chan bool
}

type ServerSearchResult struct {
	Entries    []*Entry
	Referrals  []string
	Controls   []Control
	ResultCode uint64
}

/////////////////////////
func NewServer() *Server {
	s := new(Server)
	s.quit = make(chan bool)

	d := defaultHandler{}
	s.bindFns = make(map[string]Binder)
	s.searchFns = make(map[string]Searcher)
	s.bindFns[""] = d
	s.searchFns[""] = d
	return s
}
func (server *Server) BindFunc(baseDN string, bindFn Binder) {
	server.bindFns[baseDN] = bindFn
}
func (server *Server) SearchFunc(baseDN string, searchFn Searcher) {
	server.searchFns[baseDN] = searchFn
}
func (server *Server) QuitChannel(quit chan bool) {
	server.quit = quit
}

func (server *Server) ListenAndServeTLS(listenString string, certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.ServerName = "localhost"
	ln, err := tls.Listen("tcp", listenString, &tlsConfig)
	if err != nil {
		return err
	}
	err = server.serve(ln)
	if err != nil {
		return err
	}
	return nil
}
func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}
	err = server.serve(ln)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting network connection: %s", err.Error())
				}
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			go handleConnection(c, server.bindFns, server.searchFns)
		case <-server.quit:
			ln.Close()
			break listener
		}
	}
	return nil
}

/////////////////////////
func handleConnection(conn net.Conn, bindFns map[string]Binder, searchFns map[string]Searcher) {
	boundDN := "" // "" == anonymous

handler:
	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF {
			// log.Print("Client closed connection")
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			log.Print("len(packet.Children) < 2")
			break
		}
		messageID := packet.Children[0].Value.(uint64)
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			log.Print("req.ClassType != ber.ClassApplication")
			break
		}

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			//log.Printf("Bound as %s", boundDN)
			//ber.PrintPacket(packet)
			break handler

		case ApplicationBindRequest:
			ldapResultCode := handleBindRequest(req, bindFns, conn.RemoteAddr().String())
			if ldapResultCode == LDAPResultSuccess {
				boundDN = req.Children[1].Value.(string)
			}
			responsePacket := encodeBindResponse(messageID, ldapResultCode)
			if err = sendPacket(conn, responsePacket); err != nil {
				log.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationSearchRequest:
			if err := handleSearchRequest(req, messageID, boundDN, searchFns, conn); err != nil {
				//log.Printf("handleSearchRequest error %s", err.Error())
				if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultOperationsError)); err != nil {
					log.Printf("sendPacket error %s", err.Error())
					break handler
				}
				break handler
			}
		case ApplicationUnbindRequest:
			break handler
		}
	}

	conn.Close()
}

/////////////////////////
func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())
		return err
	}
	return nil
}

/////////////////////////
func parseSearchRequest(boundDN string, req *ber.Packet) (SearchRequest, error) {
	if len(req.Children) != 8 {
		return SearchRequest{}, errors.New("Bad search request")
	}

	// Parse the request
	baseObject := req.Children[0].Value.(string)
	scope := int(req.Children[1].Value.(uint64))
	derefAliases := int(req.Children[2].Value.(uint64))
	sizeLimit := int(req.Children[3].Value.(uint64))
	timeLimit := int(req.Children[4].Value.(uint64))
	typesOnly := false
	if req.Children[5].Value != nil {
		typesOnly = req.Children[5].Value.(bool)
	}
	filter, err := DecompileFilter(req.Children[6])
	if err != nil {
		return SearchRequest{}, err
	}
	attributes := []string{}
	for _, attr := range req.Children[7].Children {
		attributes = append(attributes, attr.Value.(string))
	}
	searchReq := SearchRequest{baseObject, scope,
		derefAliases, sizeLimit, timeLimit,
		typesOnly, filter, attributes, nil}

	return searchReq, nil
}

/////////////////////////
func handleSearchRequest(req *ber.Packet, messageID uint64, boundDN string, searchFns map[string]Searcher, conn net.Conn) (resultErr error) {
	defer func() {
		if r := recover(); r != nil {
			resultErr = errors.New("search function panic")
		}
	}()

	searchReq, err := parseSearchRequest(boundDN, req)
	if err != nil {
		return err
	}

	// TODO: handle search scope (base/sub/all)

	filterPacket, err := CompileFilter(searchReq.Filter)
	if err != nil {
		return err
	}

	searchResp := searchFns[""].Search(boundDN, searchReq, conn.RemoteAddr().String()) // TODO support routing to multiple functions
	if searchResp.ResultCode != LDAPResultSuccess {
		if err = sendPacket(conn, encodeSearchDone(messageID, searchResp.ResultCode)); err != nil {
			return err
		}
		return err
	}

	for _, entry := range searchResp.Entries {
		keep, resultCode := ServerApplyFilter(filterPacket, entry)
		if resultCode != LDAPResultSuccess {
			if err = sendPacket(conn, encodeSearchDone(messageID, searchResp.ResultCode)); err != nil {
				log.Printf("sendPacket error %s", err.Error())
			}
			return err
		}
		if !keep {
			continue
		}

		if (len(searchReq.Attributes) > 1) || (len(searchReq.Attributes) == 1 && len(searchReq.Attributes[0]) > 0) {
			entry, err = filterAttributes(entry, searchReq.Attributes)
			if err != nil {
				if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultOperationsError)); err != nil {
					return err
				}
				return err
			}
		}

		responsePacket := encodeSearchResponse(messageID, searchReq, entry)
		if err = sendPacket(conn, responsePacket); err != nil {
			return err
		}
	}

	if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultSuccess)); err != nil {
		return err
	}
	return nil
}

/////////////////////////
func filterAttributes(entry *Entry, attributes []string) (*Entry, error) {
	// only return requested attributes
	newAttributes := []*EntryAttribute{}

	for _, attr := range entry.Attributes {
		for _, requested := range attributes {
			if strings.ToLower(attr.Name) == strings.ToLower(requested) {
				newAttributes = append(newAttributes, attr)
			}
		}
	}
	entry.Attributes = newAttributes

	return entry, nil
}

/////////////////////////
func handleBindRequest(req *ber.Packet, bindFns map[string]Binder, clientIP string) (resultCode uint64) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
		}
	}()

	// we only support ldapv3
	ldapVersion := req.Children[0].Value.(uint64)
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN := req.Children[1].Value.(string)
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			return bindFns[""].Bind(bindDN, bindAuth.Data.String(), clientIP) // TODO support routing to multiple functions
		} else {
			log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication
		}
	case LDAPBindAuthSASL:
		log.Print("SASL authentication is not supported")
		return LDAPResultInappropriateAuthentication
	}
	return LDAPResultOperationsError
}

/////////////////////////
type defaultHandler struct {
}

func (h defaultHandler) Bind(bindDN, bindSimplePw, clientIP string) uint64 {
	return LDAPResultInappropriateAuthentication
}
func (h defaultHandler) Search(boundDN string, searchReq SearchRequest, clientIP string) ServerSearchResult {
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}
}

/////////////////////////
func encodeBindResponse(messageID uint64, ldapResultCode uint64) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldapResultCode, "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
func encodeSearchResponse(messageID uint64, req SearchRequest, res *Entry) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
	searchEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.DN, "Object Name"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes:")
	for _, attribute := range res.Attributes {
		attrs.AppendChild(encodeSearchAttribute(attribute.Name, attribute.Values))
	}

	searchEntry.AppendChild(attrs)
	responsePacket.AppendChild(searchEntry)

	return responsePacket
}

func encodeSearchAttribute(name string, values []string) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))

	valuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
	for _, value := range values {
		valuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Attribute Value"))
	}

	packet.AppendChild(valuesPacket)

	return packet
}

func encodeSearchDone(messageID uint64, ldapResultCode uint64) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	donePacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultDone, nil, "Search result done")
	donePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldapResultCode, "resultCode: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	donePacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))
	responsePacket.AppendChild(donePacket)

	return responsePacket
}

/////////////////////////
